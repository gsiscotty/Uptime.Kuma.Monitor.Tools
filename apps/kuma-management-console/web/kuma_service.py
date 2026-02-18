"""
Kuma API service wrapper.
Adapted from the CLI tool for web usage with session-based connection management.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
import time
from datetime import datetime, timedelta

from uptime_kuma_api import UptimeKumaApi
from uptime_kuma_api.exceptions import Timeout
import pyotp


class KumaServiceError(Exception):
    """Custom exception for Kuma service errors."""
    pass


class KumaConnectionExpired(KumaServiceError):
    """Exception raised when connection/token has expired and re-auth is needed."""
    pass


class KumaService:
    """
    Service class for interacting with Uptime Kuma API.
    Manages connection lifecycle and provides high-level operations.
    """
    
    def __init__(self):
        self.api: Optional[UptimeKumaApi] = None
        self.url: str = ""
        self.connected: bool = False
        self._monitors_cache: Optional[List[dict]] = None
        self._notifications_cache: Optional[List[dict]] = None
        self._tags_cache: Optional[List[dict]] = None
        
        # Connection tracking
        self._connected_at: Optional[datetime] = None
        self._last_validated: Optional[datetime] = None
        self._uses_2fa: bool = False
        self._totp_secret: Optional[str] = None  # Store secret for auto-refresh
    
    def connect(
        self,
        url: str,
        username: str,
        password: str,
        use_2fa: bool = False,
        totp_token: str = "",
        totp_secret: str = "",
        timeout: int = 45,
        max_retries: int = 3
    ) -> Tuple[bool, str]:
        """
        Connect to Uptime Kuma.
        Returns (success, error_message).
        """
        try:
            self.disconnect()
            
            self.api = UptimeKumaApi(url)
            self.api.timeout = timeout
            self._try_force_websocket()
            
            # Login with retry logic
            last_error = None
            for attempt in range(max_retries):
                try:
                    if use_2fa:
                        # Generate token from secret if provided
                        if totp_secret:
                            token = pyotp.TOTP(totp_secret).now()
                        else:
                            token = totp_token
                        self.api.login(username, password, token=token)
                    else:
                        self.api.login(username, password)
                    
                    self.url = url
                    self.connected = True
                    self._connected_at = datetime.utcnow()
                    self._last_validated = datetime.utcnow()
                    self._uses_2fa = use_2fa
                    
                    # Store TOTP secret for auto-refresh (if provided)
                    # This allows automatic token regeneration
                    if totp_secret:
                        self._totp_secret = totp_secret
                    else:
                        self._totp_secret = None
                    
                    # Wait for connection to stabilize by verifying we can fetch data
                    # This prevents "Not connected" errors immediately after redirect
                    for stabilize_attempt in range(3):
                        try:
                            # A simple API call to verify connection is ready
                            self.api.get_monitors()
                            break  # Connection is ready
                        except Exception:
                            if stabilize_attempt < 2:
                                time.sleep(0.5)
                            # Don't fail connect on stabilization issues, just log
                    
                    return True, ""
                    
                except Exception as e:
                    last_error = e
                    error_msg = str(e).lower()
                    original_error = str(e)
                    
                    # Log the actual error for debugging
                    import logging
                    logger = logging.getLogger('gunicorn.error')
                    logger.warning(f"[KUMA] Login attempt {attempt+1} failed: {original_error}")
                    
                    # Check for 2FA/token errors FIRST (more specific)
                    if any(x in error_msg for x in ['invalid token', 'token', '2fa', 'otp', 'totp', 'two-factor', 'two factor']):
                        return False, "Invalid 2FA token. Please check your authenticator app and try again."
                    
                    # Check for credential errors
                    if any(x in error_msg for x in ['password', 'username', 'credential', 'unauthorized', 'forbidden']):
                        return False, "Invalid username or password."
                    
                    # Check for connection/timeout errors - these should retry
                    if any(x in error_msg for x in ['timeout', 'connection', 'refused', 'network', 'unreachable']):
                        if attempt < max_retries - 1:
                            time.sleep(1.5)
                            continue
                        return False, f"Connection error: {original_error}"
                    
                    # For other errors, retry
                    if attempt < max_retries - 1:
                        time.sleep(1.5)
                        continue
            
            return False, f"Connection failed after {max_retries} attempts: {last_error}"
            
        except Exception as e:
            self.disconnect()
            return False, f"Connection error: {str(e)}"
    
    def validate_connection(self) -> Tuple[bool, str]:
        """
        Validate that the connection is still active.
        Returns (is_valid, error_message).
        """
        if not self.connected or not self.api:
            return False, "Not connected"
        
        try:
            # Try to fetch monitors as a connection test
            self.api.get_monitors()
            self._last_validated = datetime.utcnow()
            return True, ""
        except Exception as e:
            error_msg = str(e).lower()
            
            # Check for session/auth errors that indicate need for re-auth
            if any(x in error_msg for x in ['unauthorized', 'invalid', 'expired', 'token', 'auth', 'login']):
                self.connected = False
                return False, "SESSION_EXPIRED"
            
            # Other errors (network, timeout, etc.)
            return False, f"Connection error: {str(e)}"
    
    def needs_reauth(self) -> bool:
        """
        Check if re-authentication is needed.
        For 2FA with token (not secret), we can't auto-refresh.
        """
        if not self.connected:
            return True
        
        # If using 2FA without stored secret, connection might be stale
        # We validate before critical operations
        if self._uses_2fa and not self._totp_secret:
            # Check if we haven't validated recently (within 5 minutes)
            if self._last_validated:
                age = (datetime.utcnow() - self._last_validated).total_seconds()
                if age > 300:  # 5 minutes
                    return True
        
        return False
    
    def can_auto_refresh(self) -> bool:
        """Check if we can auto-refresh the connection (have TOTP secret)."""
        return self._uses_2fa and self._totp_secret is not None
    
    def disconnect(self) -> None:
        """Disconnect from Uptime Kuma."""
        if self.api:
            try:
                self.api.disconnect()
            except Exception:
                pass
        self.api = None
        self.url = ""
        self.connected = False
        self._clear_cache()
    
    def _clear_cache(self) -> None:
        """Clear cached data."""
        self._monitors_cache = None
        self._notifications_cache = None
        self._tags_cache = None
    
    def _try_force_websocket(self) -> None:
        """Try to force websocket transport."""
        try:
            sio = getattr(self.api, "sio", None)
            if sio and hasattr(sio, "transports"):
                sio.transports = ["websocket"]
        except Exception:
            pass
    
    def _ensure_connected(self, validate: bool = False) -> None:
        """
        Raise error if not connected.
        If validate=True, also verify the connection is still active.
        """
        if not self.connected or not self.api:
            raise KumaServiceError("Not connected to Uptime Kuma")
        
        if validate:
            is_valid, error = self.validate_connection()
            if not is_valid:
                if error == "SESSION_EXPIRED":
                    raise KumaConnectionExpired("Session expired. Please re-authenticate with a new 2FA token.")
                raise KumaServiceError(f"Connection validation failed: {error}")
    
    def get_monitors(self, force_refresh: bool = False) -> List[dict]:
        """Get all monitors with retry logic for connection stabilization."""
        self._ensure_connected()
        if force_refresh or self._monitors_cache is None:
            # Retry logic for fresh connections that may not be fully ready
            for attempt in range(3):
                try:
                    result = self.api.get_monitors()
                    if result is not None:  # Got data (empty list is valid)
                        self._monitors_cache = result
                        return self._monitors_cache
                    elif attempt < 2:  # None result, retry
                        time.sleep(0.5)
                except Exception as e:
                    if attempt < 2:
                        time.sleep(0.5)
                        continue
                    raise
            # If we get here, return empty or cached
            self._monitors_cache = []
        return self._monitors_cache
    
    def get_monitor(self, monitor_id: int) -> dict:
        """Get a specific monitor by ID."""
        self._ensure_connected()
        return self.api.get_monitor(monitor_id)
    
    def get_notifications(self, force_refresh: bool = False) -> List[dict]:
        """Get all notifications with retry logic."""
        self._ensure_connected()
        if force_refresh or self._notifications_cache is None:
            # Sometimes the API needs a moment after connection
            # Try up to 3 times with a short delay
            for attempt in range(3):
                try:
                    result = self.api.get_notifications()
                    if result:  # Got data
                        self._notifications_cache = result
                        break
                    elif attempt < 2:  # Empty result, retry
                        time.sleep(0.5)
                except Exception as e:
                    if attempt < 2:
                        time.sleep(0.5)
                        continue
                    raise
            else:
                self._notifications_cache = []
        return self._notifications_cache or []
    
    def get_tags(self, force_refresh: bool = False) -> List[dict]:
        """Get all tags with retry logic for connection stabilization."""
        self._ensure_connected()
        if force_refresh or self._tags_cache is None:
            # Retry logic for fresh connections that may not be fully ready
            for attempt in range(3):
                try:
                    if hasattr(self.api, 'get_tags'):
                        result = self.api.get_tags()
                        if result is not None:
                            self._tags_cache = result
                            return self._tags_cache
                        elif attempt < 2:
                            time.sleep(0.5)
                    else:
                        # Fallback: collect tags from monitors
                        self._tags_cache = self._collect_tags_from_monitors()
                        return self._tags_cache
                except Exception as e:
                    if attempt < 2:
                        time.sleep(0.5)
                        continue
                    # On final attempt, try fallback
                    self._tags_cache = self._collect_tags_from_monitors()
                    return self._tags_cache
            # If we get here, return empty or fallback
            self._tags_cache = self._collect_tags_from_monitors() if self._monitors_cache else []
        return self._tags_cache
    
    def _collect_tags_from_monitors(self) -> List[dict]:
        """Collect unique tags from all monitors."""
        monitors = self.get_monitors()
        tags_map: Dict[str, dict] = {}
        for m in monitors:
            for tag in m.get('tags', []):
                if isinstance(tag, dict):
                    name = tag.get('name', '')
                    if name and name not in tags_map:
                        tags_map[name] = tag
        return list(tags_map.values())
    
    def get_groups(self) -> List[dict]:
        """Get all group monitors."""
        monitors = self.get_monitors()
        groups = []
        for m in monitors:
            if self.is_group_monitor(m):
                groups.append({
                    'id': m.get('id'),
                    'name': m.get('name', ''),
                })
        return groups
    
    @staticmethod
    def is_group_monitor(monitor: dict) -> bool:
        """Check if a monitor is a group/container monitor."""
        mtype = str(monitor.get("type", "")).strip().lower()
        
        if "group" in mtype:
            return True
        
        children_ids = monitor.get("childrenIDs")
        if isinstance(children_ids, list) and len(children_ids) > 0:
            has_url = monitor.get("url") or monitor.get("hostname") or monitor.get("address")
            if not has_url:
                return True
        
        if monitor.get("id") and monitor.get("name"):
            has_url = monitor.get("url")
            has_hostname = monitor.get("hostname")
            has_address = monitor.get("address")
            has_method = monitor.get("method")
            if not (has_url or has_hostname or has_address or has_method):
                if "childrenIDs" in monitor:
                    return True
        
        return False
    
    def filter_monitors(
        self,
        include_tags: List[str] = None,
        exclude_tags: List[str] = None,
        tag_match_mode: str = "all",
        name_filters: List[str] = None,
        name_match_mode: str = "partial",
        skip_groups: bool = False,
        only_groups: bool = False,
        group_names: List[str] = None,
        only_active: bool = False
    ) -> List[dict]:
        """
        Filter monitors based on criteria.
        Returns list of matching monitors.
        """
        monitors = self.get_monitors(force_refresh=True)
        
        # Normalize filter inputs
        include_set = {t.strip().lower() for t in (include_tags or []) if t.strip()}
        exclude_set = {t.strip().lower() for t in (exclude_tags or []) if t.strip()}
        name_filters = [n.strip() for n in (name_filters or []) if n.strip()]
        group_names = [g.strip().lower() for g in (group_names or []) if g.strip()]
        
        # Build group ID map
        group_name_to_id: Dict[str, int] = {}
        group_id_to_name: Dict[int, str] = {}
        for m in monitors:
            if self.is_group_monitor(m) and isinstance(m.get("id"), int):
                gid = int(m["id"])
                gname = str(m.get("name", "")).strip()
                if gname:
                    group_name_to_id[gname.lower()] = gid
                    group_id_to_name[gid] = gname
        
        # Get target group IDs
        target_group_ids: Set[int] = set()
        if group_names:
            for gn in group_names:
                if gn in group_name_to_id:
                    target_group_ids.add(group_name_to_id[gn])
        
        results = []
        for m in monitors:
            mid = m.get("id")
            name = m.get("name", "")
            active = bool(m.get("active", True))
            
            if not isinstance(mid, int):
                continue
            
            if only_active and not active:
                continue
            
            # Group filtering
            if only_groups:
                if not self.is_group_monitor(m):
                    continue
            elif skip_groups and self.is_group_monitor(m):
                continue
            
            # Tag filtering
            monitor_tags = self._get_monitor_tag_names(m)
            
            if exclude_set and exclude_set.intersection(monitor_tags):
                continue
            
            if include_set:
                if tag_match_mode == "all":
                    if not include_set.issubset(monitor_tags):
                        continue
                else:  # any
                    if not include_set.intersection(monitor_tags):
                        continue
            
            # Name filtering
            if name_filters:
                name_lower = name.lower()
                match_found = False
                for nf in name_filters:
                    nf_lower = nf.lower()
                    if name_match_mode == "full":
                        if name_lower == nf_lower:
                            match_found = True
                            break
                    else:  # partial
                        if nf_lower in name_lower:
                            match_found = True
                            break
                if not match_found:
                    continue
            
            # Group membership filtering
            if target_group_ids:
                parent = m.get("parent")
                if not isinstance(parent, int) or parent not in target_group_ids:
                    continue
            
            # Add group info
            parent_id = m.get("parent")
            m['_group_name'] = group_id_to_name.get(parent_id, "") if isinstance(parent_id, int) else ""
            m['_tags'] = list(monitor_tags)
            
            results.append(m)
        
        return results
    
    def _get_monitor_tag_names(self, monitor: dict) -> Set[str]:
        """Get normalized tag names from a monitor."""
        tags = monitor.get("tags", [])
        names: Set[str] = set()
        if isinstance(tags, list):
            for t in tags:
                if isinstance(t, dict):
                    nm = t.get("name")
                    if isinstance(nm, str) and nm.strip():
                        names.add(nm.strip().lower())
        return names
    
    def edit_monitor(self, monitor_id: int, **kwargs) -> bool:
        """Edit a monitor's properties."""
        # Validate connection before making changes
        self._ensure_connected(validate=True)
        try:
            self.api.edit_monitor(monitor_id, **kwargs)
            self._monitors_cache = None  # Invalidate cache
            return True
        except Exception as e:
            raise KumaServiceError(f"Failed to edit monitor {monitor_id}: {e}")
    
    def add_monitor_tag(self, monitor_id: int, tag_id: int) -> bool:
        """Add a tag to a monitor."""
        # Validate connection before making changes
        self._ensure_connected(validate=True)
        try:
            self.api.add_monitor_tag(tag_id=tag_id, monitor_id=monitor_id)
            self._monitors_cache = None
            return True
        except Exception as e:
            raise KumaServiceError(f"Failed to add tag {tag_id} to monitor {monitor_id}: {e}")
    
    def delete_monitor_tag(self, monitor_id: int, tag_id: int) -> bool:
        """Remove a tag from a monitor."""
        # Validate connection before making changes
        self._ensure_connected(validate=True)
        try:
            self.api.delete_monitor_tag(tag_id=tag_id, monitor_id=monitor_id)
            self._monitors_cache = None
            return True
        except Exception as e:
            raise KumaServiceError(f"Failed to remove tag {tag_id} from monitor {monitor_id}: {e}")
    
    def delete_monitor(self, monitor_id: int) -> bool:
        """Delete a monitor permanently."""
        # Validate connection before making changes
        self._ensure_connected(validate=True)
        try:
            self.api.delete_monitor(monitor_id)
            self._monitors_cache = None
            return True
        except Exception as e:
            raise KumaServiceError(f"Failed to delete monitor {monitor_id}: {e}")
    
    # =========================================================================
    # System Management - Tags
    # =========================================================================
    def create_tag(self, name: str, color: str = "#4B5563") -> dict:
        """Create a new tag in the system."""
        self._ensure_connected(validate=True)
        try:
            result = self.api.add_tag(name=name, color=color)
            return result
        except Exception as e:
            raise KumaServiceError(f"Failed to create tag '{name}': {e}")
    
    def delete_tag(self, tag_id: int) -> bool:
        """Delete a tag from the system."""
        self._ensure_connected(validate=True)
        try:
            self.api.delete_tag(tag_id)
            return True
        except Exception as e:
            raise KumaServiceError(f"Failed to delete tag {tag_id}: {e}")
    
    def edit_tag(self, tag_id: int, name: str = None, color: str = None) -> bool:
        """Edit an existing tag."""
        self._ensure_connected(validate=True)
        try:
            kwargs = {}
            if name is not None:
                kwargs['name'] = name
            if color is not None:
                kwargs['color'] = color
            if kwargs:
                self.api.edit_tag(tag_id, **kwargs)
            return True
        except Exception as e:
            raise KumaServiceError(f"Failed to edit tag {tag_id}: {e}")
    
    # =========================================================================
    # System Management - Groups
    # =========================================================================
    def create_group(self, name: str) -> dict:
        """Create a new monitor group."""
        self._ensure_connected(validate=True)
        try:
            result = self.api.add_monitor(type="group", name=name)
            self._monitors_cache = None
            return result
        except Exception as e:
            raise KumaServiceError(f"Failed to create group '{name}': {e}")
    
    def delete_group(self, group_id: int) -> bool:
        """Delete a monitor group (must be empty)."""
        self._ensure_connected(validate=True)
        try:
            self.api.delete_monitor(group_id)
            self._monitors_cache = None
            return True
        except Exception as e:
            raise KumaServiceError(f"Failed to delete group {group_id}: {e}")
    
    def bulk_edit(
        self,
        monitor_ids: List[int],
        changes: dict,
        stop_on_error: bool = False
    ) -> Tuple[int, int, List[str]]:
        """
        Apply changes to multiple monitors.
        
        Args:
            monitor_ids: List of monitor IDs to edit
            changes: Dict of changes to apply
            stop_on_error: Stop processing on first error
        
        Returns:
            Tuple of (success_count, error_count, error_messages)
        """
        import logging
        logger = logging.getLogger('gunicorn.error')
        
        # Validate connection before making any changes
        logger.info(f"[BULK_EDIT] Starting bulk edit for {len(monitor_ids)} monitors")
        logger.info(f"[BULK_EDIT] Changes requested: {changes}")
        self._ensure_connected(validate=True)
        
        success = 0
        errors = 0
        error_messages = []
        
        # Extract special change types that need per-monitor handling
        # Make copies to avoid modifying original dict
        notification_action = changes.pop('notificationAction', None)
        notification_ids = changes.pop('notificationIds', [])
        tag_action = changes.pop('tagAction', None)
        tag_ids = changes.pop('tagIds', [])
        
        logger.info(f"[BULK_EDIT] Notification action: {notification_action}, IDs: {notification_ids}")
        logger.info(f"[BULK_EDIT] Tag action: {tag_action}, IDs: {tag_ids}")
        logger.info(f"[BULK_EDIT] Other changes: {changes}")
        
        for mid in monitor_ids:
            try:
                logger.info(f"[BULK_EDIT] Processing monitor {mid}")
                monitor_changes = {}
                
                # Get current monitor state for actions that need it
                current_monitor = None
                if notification_action or tag_action:
                    current_monitor = self.api.get_monitor(mid)
                
                # Handle notification changes
                if notification_action and notification_ids:
                    current_notifs = set(current_monitor.get('notificationIDList', []) if current_monitor else [])
                    new_ids = set(notification_ids)
                    
                    if notification_action == 'add':
                        final_notifs = list(current_notifs | new_ids)
                    elif notification_action == 'remove':
                        final_notifs = list(current_notifs - new_ids)
                    elif notification_action == 'set':
                        final_notifs = list(new_ids)
                    else:
                        final_notifs = list(current_notifs)
                    
                    monitor_changes['notificationIDList'] = final_notifs
                    logger.info(f"[BULK_EDIT] Monitor {mid}: notificationIDList {list(current_notifs)} -> {final_notifs}")
                
                # Handle tag changes
                if tag_action and tag_ids:
                    current_tags = {t.get('tag_id') or t.get('id') for t in current_monitor.get('tags', []) if isinstance(t, dict)}
                    new_tags = set(tag_ids)
                    
                    if tag_action == 'add':
                        # Add tags that aren't already present
                        for tag_id in new_tags - current_tags:
                            try:
                                self.api.add_monitor_tag(tag_id=tag_id, monitor_id=mid)
                            except Exception as te:
                                logger.warning(f"[BULK_EDIT] Failed to add tag {tag_id} to monitor {mid}: {te}")
                    elif tag_action == 'remove':
                        # Remove tags
                        for tag_id in new_tags & current_tags:
                            try:
                                self.api.delete_monitor_tag(tag_id=tag_id, monitor_id=mid)
                            except Exception as te:
                                logger.warning(f"[BULK_EDIT] Failed to remove tag {tag_id} from monitor {mid}: {te}")
                
                # Add other changes
                monitor_changes.update(changes)
                
                # Apply changes if any
                if monitor_changes:
                    logger.info(f"[BULK_EDIT] Applying to monitor {mid}: {monitor_changes}")
                    self.api.edit_monitor(mid, **monitor_changes)
                
                success += 1
                logger.info(f"[BULK_EDIT] Monitor {mid}: SUCCESS")
                
            except Exception as e:
                errors += 1
                error_msg = f"Monitor {mid}: {str(e)}"
                error_messages.append(error_msg)
                logger.error(f"[BULK_EDIT] {error_msg}")
                if stop_on_error:
                    break
        
        self._monitors_cache = None  # Invalidate cache
        logger.info(f"[BULK_EDIT] Completed: {success} success, {errors} errors")
        return success, errors, error_messages
    
    def build_notification_maps(self) -> Tuple[Dict[str, Tuple[int, str]], Dict[int, str]]:
        """
        Build notification lookup maps.
        Returns (name_map, id_map).
        name_map: normalized_name -> (id, original_name)
        id_map: id -> name
        """
        notifications = self.get_notifications()
        name_map: Dict[str, Tuple[int, str]] = {}
        id_map: Dict[int, str] = {}
        
        for n in notifications:
            nid = n.get("id")
            name = n.get("name")
            if isinstance(nid, int) and isinstance(name, str) and name.strip():
                name_map[name.strip().lower()] = (nid, name.strip())
                id_map[nid] = name.strip()
        
        return name_map, id_map
    
    def build_tag_maps(self) -> Tuple[Dict[str, int], Dict[int, str]]:
        """
        Build tag lookup maps.
        Returns (name_to_id, id_to_name).
        """
        tags = self.get_tags()
        name_to_id: Dict[str, int] = {}
        id_to_name: Dict[int, str] = {}
        
        for t in tags:
            tid = t.get("id")
            name = t.get("name")
            if isinstance(tid, int) and isinstance(name, str) and name.strip():
                name_to_id[name.strip().lower()] = tid
                id_to_name[tid] = name.strip()
        
        return name_to_id, id_to_name
