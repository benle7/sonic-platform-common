"""
    bmc_base.py

    Base class for implementing a platform-specific class with which
    to interact with a BMC device in SONiC.
"""


from . import device_base

class BMCBase(device_base.DeviceBase):

    def get_eeprom(self):
        """
        Retrieves the BMC EEPROM information

        Returns:
            A dictionary containing the BMC EEPROM information
            Returns an empty dictionary {} if EEPROM information cannot be retrieved
        """
        raise NotImplementedError
    
    def get_version(self):
        """
        Retrieves the BMC firmware version

        Returns:
            A string containing the BMC firmware version.
            Returns 'N/A' if the BMC firmware version cannot be retrieved
        """
        raise NotImplementedError
    
    def reset_root_password(self):
        """
        Resets the BMC root password to default

        Returns:
            A tuple (ret, msg) where:
                ret: An integer return code indicating success (0) or failure
                msg: A string containing success message or error description
        """
        raise NotImplementedError
    
    def trigger_bmc_debug_log_dump(self):
        """
        Triggers a BMC debug log dump operation

        Returns:
            A tuple (ret, (task_id, err_msg)) where:
                ret: An integer return code indicating success (0) or failure
                task_id: A string containing the Redfish task ID for monitoring
                         the debug log dump operation. Returns '-1' on failure.
                err_msg: A string containing error message if operation failed,
                        None if successful
        """
        raise NotImplementedError
    
    def get_bmc_debug_log_dump(self, task_id, filename, path, timeout = 120):
        """
        Retrieves the BMC debug log dump for a given task ID and saves it to
        the specified file path

        Args:
            task_id: A string containing the task ID from trigger_bmc_debug_log_dump
            filename: A string containing the filename to save the debug log
            path: A string containing the directory path where to save the debug log
            timeout: An integer, timeout in seconds for the operation (default: 120)

        Returns:
            A tuple (ret, err_msg) where:
                ret: An integer return code indicating success (0) or failure
                err_msg: A string containing error message if operation failed
        """
        raise NotImplementedError
    
    def update_firmware(self, fw_image):
        """
        Updates the BMC firmware with the provided firmware image

        Args:
            fw_image: A string containing the path to the firmware image file

        Returns:
            A tuple (ret, msg) where:
                ret: An integer return code indicating success (0) or failure
                msg: A string containing status message about the firmware update
        """
        raise NotImplementedError
