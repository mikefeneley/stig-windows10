#/usr/bin/python
from windows10_system_auditor import Windows10SystemAuditor

import platform


class Windows10Auditor:

    def __init__(self):
        system = platform.system()
        release = platform.release()

        if(system != "Windows" and release != "10"):
            print(system, release)
            print("Operating system not supported for windows 10 audit.")
            exit()

    def audit(self):
        """
        Entry fucntion to the auditor creates other auditing objects and uses
        them to audit componenets of the Windows 10 configuration for STIG
        compliance.

        :returns: string -- filename of the log file
        """
        files = []

        system_auditor = Windows10SystemAuditor()
        filename = system_auditor.audit()
        if filename != 0:
            files.append(filename)
        self.built_output(files)
        print("Begin Hellog")
        print(filename, type(filename))
        print("ENd Hello")
        return filename

    def built_output(self, files, filename="Windows10Log.txt"):
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
    auditor = Windows10Auditor()
    auditor.audit()
