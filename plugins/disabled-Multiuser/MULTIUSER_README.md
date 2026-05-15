# Multiuser Plugin

**Main Features:**  
- Mode settings: access the entire network, or allow only listed sites.  
- Adding existing sites can be allowed or blocked (`multiuser_no_new_sites`).  
  - `True` → adding existing sites allowed (default) **allowed** (default)  
  - `False` → adding existing sites allowed (default) **blocked**, in which case the user receives the following **error message**:  
    ```
    Not Found
    Adding new sites disabled on this proxy
    ```
- Users listed in `local_master_addresses` can **always add sites.**.  

**Configuration and Editing:**  
- Open the **`MultiuserPlugin.py`** file in Notepad++ or any other text editor.  
- Change the `config.multiuser_no_new_sites` value according to your desired behavior.