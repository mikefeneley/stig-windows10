
from windows10_system_logger import Windows10SystemLogger
from windows10_winrm_auditor import Windows10WinRMAuditor
from windows10_tmp_sys_auditor import Windows10TmpSysAuditor

from winreg_comparator import WinRegComparator

import platform


if platform.system() == "Windows":
    from _winreg import *



class Windows10SystemAuditor:

    """
    This class currently audits most of the register access configuration
    functions. My plan is to break it into subclasses which audits specific
    characteristics of windows 10 system.
    """

    def __init__(self):
        self.comparator = WinRegComparator()

    def audit(self):
        """
        Entry function to all system defined requirments by the
        Windows 10 STIG.

        :returns: string -- filename of the log file
        """
        files = []
        winrm_auditor = Windows10WinRMAuditor()
        tmp_sys_auditor = Windows10TmpSysAuditor()
        
        filename = winrm_auditor.audit()
        if filename != 0:
            files.append(filename)
        filename = tmp_sys_auditor.audit()
        if filename != 0:
            files.append(filename)


        filename = self.build_output(files)

        return filename


    def build_output(self, files, filename="Windows10SystemAudit.txt"):
        """
        Concatenates all the log files in files list into single file
        with name filename.
        :returns: string -- filename of the log file
        """
        out_log = open(filename, 'w')

        for file in files:
            in_log = open(file, 'r')

            for line in in_log:
                out_log.write(line)
            in_log.close()

        out_log.close()
        return filename

if __name__ == "__main__":
    auditor = Windows10SystemAuditor()
    auditor.audit()