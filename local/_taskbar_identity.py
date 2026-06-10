"""Rebrand an Edge --app window's Windows taskbar identity to ours.

Without this, Edge --app windows inherit msedge.exe's AppUserModelID, so the
Windows taskbar groups them under Edge and shows the Edge icon. Setting an
explicit AppUserModelID + RelaunchIconResource on the window's IPropertyStore
makes Windows treat it as a distinct app and use our icon.

Pure stdlib (ctypes). No-op on non-Windows. Failures are swallowed —
launcher must not crash if the icon rebrand cannot be applied.
"""
from __future__ import annotations

import sys
import time
import ctypes
import ctypes.wintypes as wt
from ctypes import POINTER, byref, c_void_p, c_wchar_p


def apply_taskbar_identity(pid: int,
                           app_id: str,
                           exe_path: str,
                           display_name: str = "ADK Cyber AI",
                           timeout_sec: float = 15.0,
                           poll_interval: float = 0.25) -> bool:
    """Poll for the visible top-level window of `pid` and set its
    AppUserModelID + relaunch icon. Returns True on success."""
    if sys.platform != "win32":
        return False
    try:
        return _apply(pid, app_id, exe_path, display_name,
                      timeout_sec, poll_interval)
    except Exception:
        return False


# ─── Win32 / COM plumbing ────────────────────────────────────────────────────

_S_OK = 0
_COINIT_APARTMENTTHREADED = 0x2


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _PROPERTYKEY(ctypes.Structure):
    _fields_ = [
        ("fmtid", _GUID),
        ("pid",   ctypes.c_uint32),
    ]


# Full 16-byte PROPVARIANT (vt + 3 reserved words + 8-byte union)
class _PROPVARIANT(ctypes.Structure):
    _fields_ = [
        ("vt",         ctypes.c_uint16),
        ("wReserved1", ctypes.c_uint16),
        ("wReserved2", ctypes.c_uint16),
        ("wReserved3", ctypes.c_uint16),
        ("data1",      ctypes.c_uint64),
        ("data2",      ctypes.c_uint64),
    ]


def _g(d1, d2, d3, *d4) -> _GUID:
    return _GUID(d1, d2, d3, (ctypes.c_ubyte * 8)(*d4))


# IID_IPropertyStore {886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99}
_IID_IPropertyStore = _g(
    0x886D8EEB, 0x8CF2, 0x4446,
    0x8D, 0x02, 0xCD, 0xBA, 0x1D, 0xBD, 0xCF, 0x99,
)

# AppUserModel namespace fmtid {9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}
_FMTID_AUM = _g(
    0x9F4C2855, 0x9F79, 0x4B39,
    0xA8, 0xD0, 0xE1, 0xD4, 0x2D, 0xE1, 0xD5, 0xF3,
)

_PKEY_ID            = _PROPERTYKEY(_FMTID_AUM, 5)
_PKEY_RELAUNCH_CMD  = _PROPERTYKEY(_FMTID_AUM, 2)
_PKEY_RELAUNCH_ICON = _PROPERTYKEY(_FMTID_AUM, 3)
_PKEY_RELAUNCH_NAME = _PROPERTYKEY(_FMTID_AUM, 4)


_user32  = ctypes.WinDLL("user32",  use_last_error=True) if sys.platform == "win32" else None
_shell32 = ctypes.WinDLL("shell32", use_last_error=True) if sys.platform == "win32" else None
_ole32   = ctypes.WinDLL("ole32",   use_last_error=True) if sys.platform == "win32" else None
_propsys = ctypes.WinDLL("propsys", use_last_error=True) if sys.platform == "win32" else None

if sys.platform == "win32":
    _ENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)

    _user32.EnumWindows.argtypes               = [_ENUMPROC, wt.LPARAM]
    _user32.EnumWindows.restype                = ctypes.c_bool
    _user32.GetWindowThreadProcessId.argtypes  = [wt.HWND, POINTER(wt.DWORD)]
    _user32.GetWindowThreadProcessId.restype   = wt.DWORD
    _user32.IsWindowVisible.argtypes           = [wt.HWND]
    _user32.IsWindowVisible.restype            = ctypes.c_bool
    _user32.GetWindowTextLengthW.argtypes      = [wt.HWND]
    _user32.GetWindowTextLengthW.restype       = ctypes.c_int

    _shell32.SHGetPropertyStoreForWindow.argtypes = [wt.HWND, POINTER(_GUID), POINTER(c_void_p)]
    _shell32.SHGetPropertyStoreForWindow.restype  = ctypes.HRESULT

    _propsys.InitPropVariantFromString.argtypes = [c_wchar_p, POINTER(_PROPVARIANT)]
    _propsys.InitPropVariantFromString.restype  = ctypes.HRESULT

    _ole32.PropVariantClear.argtypes = [POINTER(_PROPVARIANT)]
    _ole32.PropVariantClear.restype  = ctypes.HRESULT

    _ole32.CoInitializeEx.argtypes = [c_void_p, ctypes.c_uint32]
    _ole32.CoInitializeEx.restype  = ctypes.HRESULT
    _ole32.CoUninitialize.argtypes = []
    _ole32.CoUninitialize.restype  = None


def _find_visible_windows(pid: int) -> list:
    """Top-level visible windows owned by `pid` that have a title bar."""
    hwnds: list = []

    @_ENUMPROC
    def cb(hwnd, _lparam):
        win_pid = wt.DWORD()
        _user32.GetWindowThreadProcessId(hwnd, byref(win_pid))
        if win_pid.value == pid and _user32.IsWindowVisible(hwnd):
            if _user32.GetWindowTextLengthW(hwnd) > 0:
                hwnds.append(int(hwnd))
        return True

    _user32.EnumWindows(cb, 0)
    return hwnds


def _set_props_on_hwnd(hwnd: int, app_id: str, exe_path: str,
                       display_name: str) -> bool:
    store = c_void_p()
    hr = _shell32.SHGetPropertyStoreForWindow(
        wt.HWND(hwnd), byref(_IID_IPropertyStore), byref(store)
    )
    if hr != _S_OK or not store.value:
        return False

    # IPropertyStore vtable layout (IUnknown + 5 methods):
    #   0: QueryInterface, 1: AddRef, 2: Release,
    #   3: GetCount, 4: GetAt, 5: GetValue, 6: SetValue, 7: Commit
    vtable_ptr_ptr = ctypes.cast(store, POINTER(c_void_p))
    vtable = ctypes.cast(vtable_ptr_ptr[0], POINTER(c_void_p))

    SetValueProto = ctypes.WINFUNCTYPE(
        ctypes.HRESULT, c_void_p, POINTER(_PROPERTYKEY), POINTER(_PROPVARIANT)
    )
    CommitProto  = ctypes.WINFUNCTYPE(ctypes.HRESULT, c_void_p)
    ReleaseProto = ctypes.WINFUNCTYPE(ctypes.c_uint32, c_void_p)

    set_value = SetValueProto(vtable[6])
    commit    = CommitProto(vtable[7])
    release   = ReleaseProto(vtable[2])

    def _set_str(key: _PROPERTYKEY, value: str) -> bool:
        pv = _PROPVARIANT()
        if _propsys.InitPropVariantFromString(value, byref(pv)) != _S_OK:
            return False
        try:
            return set_value(store, byref(key), byref(pv)) == _S_OK
        finally:
            _ole32.PropVariantClear(byref(pv))

    try:
        ok = (
            _set_str(_PKEY_ID,            app_id) and
            _set_str(_PKEY_RELAUNCH_CMD,  f'"{exe_path}"') and
            _set_str(_PKEY_RELAUNCH_ICON, f'{exe_path},0') and
            _set_str(_PKEY_RELAUNCH_NAME, display_name)
        )
        if ok:
            commit(store)
        return ok
    finally:
        release(store)


def _apply(pid: int, app_id: str, exe_path: str, display_name: str,
           timeout_sec: float, poll_interval: float) -> bool:
    # COM must be initialised on the thread that calls SHGetPropertyStoreForWindow.
    _ole32.CoInitializeEx(None, _COINIT_APARTMENTTHREADED)
    try:
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            for hwnd in _find_visible_windows(pid):
                if _set_props_on_hwnd(hwnd, app_id, exe_path, display_name):
                    return True
            time.sleep(poll_interval)
        return False
    finally:
        _ole32.CoUninitialize()
