import subprocess

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, Heuristic

class ClamAV(ServiceBase):
    def __init__(self, config=None):
        super(ClamAV, self).__init__(config)

    def start(self):
        self.log.debug("ClamAV service started")

    def stop(self):
        self.log.debug("ClamAV service ended")

    def execute(self, request):
        result = Result()
        file_path = request.file_path

        try:
            clamscan_cmd = "clamscan -a -z --detect-pua --alert-macros " + file_path
            p1 = subprocess.Popen(clamscan_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p1.wait()
            stdout, stderr = p1.communicate()

            if p1.returncode == 0:
                report = stdout.decode("utf-8").split("\n")
                report = list(filter(None, report))

                text_section = ResultSection("Successfully scanned the file")
                if "FOUND" in report[0]:
                    text_section.add_heuristic(Heuristic(1, "ClamAV Found Malicious Content"))

                for line in report:
                    text_section.add_line(line)
                
                result.add_section(text_section)

            else:
                result.set_error("ClamAV scan failed with exit code: {}".format(p1.returncode))
                result.add_section(ResultSection("ClamAV Error Details", body=stderr.decode("utf-8")))

        except Exception as e:
            result.set_error("An error occurred during the scan: {}".format(e))
        
        request.result = result
