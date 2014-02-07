configuration = {
    "config_path_sep": "\\",
    "plugin_only": False,
    "paths": {
        # "idascope_root_dir": "C:\\Program Files\\IDA 6.3\\plugins",
        "idascope_root_dir": "",
        "semantics_file": "idascope\\data\\semantics.json",
        "semantics_folder": "idascope\\data\\semantics",
        "winapi_keywords_file": "idascope\\data\\winapi_keywords.json",
        "winapi_rootdir": "C:\\WinAPI\\"
        },
    "winapi": {
        "search_hotkey": "ctrl+y",
        "load_keyword_database": True,
        "online_enabled": True
        },
    "inspection": {
        "default_semantics": "win-ring3"
        },
    "yara": {
        "yara_sigs": ["C:\\yara"]
        }
}
