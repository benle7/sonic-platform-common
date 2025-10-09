"""
    bmc_base.py

    Base class for implementing BMC APIs using Redfish commands.
    The vendor-specific BMC class should inherit this class and:
    1. Implement the static method get_instance() to return the singleton instance.
    2. Implement the pure virtual functions.
    3. Override other methods if necessary.
    4. Extend the class if necessary.

"""


try:
    import subprocess
    from . import device_base
    from .redfish_client import RedfishClient
    from sonic_py_common import device_info
    from sonic_py_common.logger import Logger
except ImportError as e:
    raise ImportError (str(e) + "- required module not found")


logger = Logger('bmc_base')


class BMCBase(device_base.DeviceBase):

    CURL_PATH = '/usr/bin/curl'
    BMC_NAME = 'BMC'
    BMC_FIRMWARE_ID = 'MGX_FW_BMC_0'
    BMC_EEPROM_ID = 'BMC_eeprom'
    ROOT_ACCOUNT = 'root'
    ROOT_ACCOUNT_DEFAULT_PASSWORD = '0penBmcTempPass!'
    
    def __init__(self, addr):
        """
        Initialize BMC base class.
        The vendor-specific BMC class should have get_instance() static method.
        """
        self.addr = addr
        self.rf_client = RedfishClient(BMCBase.CURL_PATH,
                                        addr,
                                        self._get_login_user_callback,
                                        self._get_login_password_callback)
    
    def _get_login_user_callback(self):
        """
        Get BMC username/account for login before Redfish commands from NOS.
        Should be implemented by vendor-specific BMC class.
        
        Returns:
            A string containing the BMC login user name
        """
        raise NotImplementedError
    
    def _get_login_password_callback(self):
        """
        Get BMC password of the account for login before Redfish commands from NOS.
        Should be implemented by vendor-specific BMC class.

        Returns:
            A string containing the BMC login password
        """
        raise NotImplementedError

    def _get_ip_addr(self):
        """Get BMC IP address"""
        return self.addr
    
    def _login(self):
        """
        Generic BMC login, should be called before any Redfish command.
        Vendor-specific BMC class may override this method for custom login behavior.
        """
        if self.rf_client.has_login():
            return RedfishClient.ERR_CODE_OK
        return self.rf_client.login()
    
    def _logout(self):
        """Generic BMC logout, should be called after any Redfish command."""
        if self.rf_client.has_login():
            return self.rf_client.logout()
        return RedfishClient.ERR_CODE_OK
    
    def _change_login_password(self, password, user=None):
        """Generic login password change"""
        return self.rf_client.redfish_api_change_login_password(password, user)
    
    def _request_bmc_reset(self, graceful=True):
        """Generic BMC reset request"""
        bmc_reset_type = RedfishClient.BMC_RESET_TYPE_GRACEFUL_RESTART if graceful else RedfishClient.BMC_RESET_TYPE_FORCE_RESTART
        return self.rf_client.redfish_api_request_bmc_reset(bmc_reset_type=bmc_reset_type)
    
    def _get_firmware_version(self, fw_id):
        return self.rf_client.redfish_api_get_firmware_version(fw_id)

    def _get_eeprom_info(self, eeprom_id):
        return self.rf_client.redfish_api_get_eeprom_info(eeprom_id)
    
    def _is_bmc_eeprom_content_valid(self, eeprom_info):
        if None == eeprom_info or 0 == len(eeprom_info):
            return False
        got_error = eeprom_info.get('error')
        if got_error:
            logger.log_error(f'Got error when querying eeprom: {got_error}')
            return False
        return True

    def get_name(self):
        return BMCBase.BMC_NAME
    
    def get_presence(self):
        bmc_data = device_info.get_bmc_data()
        if bmc_data and bmc_data.get('bmc_addr'):
            return True
        return False
    
    def get_model(self):
        eeprom_info = self.get_eeprom()
        if not self._is_bmc_eeprom_content_valid(eeprom_info):
            return None
        return eeprom_info.get('Model')
    
    def get_serial(self):
        eeprom_info = self.get_eeprom()
        if not self._is_bmc_eeprom_content_valid(eeprom_info):
            return None
        return eeprom_info.get('SerialNumber')

    def get_revision(self):
        return 'N/A'
    
    def get_status(self):
        if not self.get_presence():
            return False
        try:
            command = ['/usr/bin/ping', '-c', '1', '-W', '1', self._get_ip_addr()]
            subprocess.check_output(command, stderr=subprocess.STDOUT)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def is_replaceable(self):
        return False
    
    def get_eeprom(self):
        """
        Retrieves the BMC EEPROM information

        Returns:
            A dictionary containing the BMC EEPROM information
            Returns an empty dictionary {} if EEPROM information cannot be retrieved
        """
        try:
            ret, eeprom_info = self._get_eeprom_info(BMCBase.BMC_EEPROM_ID)
            if ret != RedfishClient.ERR_CODE_OK:
                logger.log_error(f'Failed to get BMC EEPROM info: {ret}')
            return eeprom_info
        except Exception as e:
            logger.log_error(f'Failed to get BMC EEPROM info: {str(e)}')
            return {}

    def get_version(self):
        """
        Retrieves the BMC firmware version

        Returns:
            A string containing the BMC firmware version.
            Returns 'N/A' if the BMC firmware version cannot be retrieved
        """
        ret = 0
        version = 'N/A'
        try:
            ret, version = self._get_firmware_version(BMCBase.BMC_FIRMWARE_ID)
        except Exception as e:
            logger.log_error(f'Failed to get BMC firmware version: {str(e)}')  
        if ret != RedfishClient.ERR_CODE_OK:
            return 'N/A'
        return version

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
        return self.rf_client.redfish_api_trigger_bmc_debug_log_dump()
    
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
        return self.rf_client.redfish_api_get_bmc_debug_log_dump(task_id, filename, path, timeout)

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
        logger.log_notice(f'Installing BMC firmware image {fw_image}')
        ret, msg = self.rf_client.redfish_api_update_firmware(fw_image, fw_ids=[BMCBase.BMC_FIRMWARE_ID])
        logger.log_notice(f'Firmware update result: {ret}')
        if msg:
            logger.log_notice(f'{msg}')
        return (ret, msg)

    def reset_root_password(self):
        """
        Resets the BMC root password to default

        Returns:
            A tuple (ret, msg) where:
                ret: An integer return code indicating success (0) or failure
                msg: A string containing success message or error description
        """
        return self._change_login_password(BMCBase.ROOT_ACCOUNT_DEFAULT_PASSWORD, BMCBase.ROOT_ACCOUNT)
