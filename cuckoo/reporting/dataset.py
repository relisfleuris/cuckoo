import os
import json
import codecs

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError
from cuckoo.misc import cwd, version, decide_cwd

class Dataset(Report):
    """Saves analysis results in CSV format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        api_list = ["CreateFile","CreateMutant", "CreateProcess", "CreateRemoteThread",
         "CreateService", "DeleteFile", "FindWindow", "OpenMutant",
         "OpenSCManager", "ReadFile", "ReadProcessMemory", "RegDeleteKey",
         "RegEnumKey", "RegEnumValue", "RegOpenKey", "ShellExecute",
         "TerminateProcess", "URLDownloadToFile", "WriteFile", "WriteProcessMemory"]
        api_results = []
        result = 0
        #string_attr = ""
        try:

            #json.dump(results, report, sort_keys=False, indent=4)
            #report.write(results)
            apistats = results["behavior"]["apistats"]
            classification = results["info"]["custom"]
            duration = results["info"]["duration"]
            pe_id = results["info"]["id"]
            for a in api_list:
                for process, values in apistats.iteritems():
                    #print process
                    for api, freq in values.iteritems():
                        #print api
                        if a in api:
                            result +=freq
                            #print(api, freq)
                #string_attr.append(result)
                api_results.append(result)
                result = 0
            behavior = results["behavior"]
            try:
                dropped = results["dropped"]
            except:
                #vazio = length 0
                dropped = []
            try:
                hosts = results["network"]["hosts"]
            except:
                #vazio = length 0
                hosts = []
            csv_results = "".join(str(res)+',' for res in api_results)
            #print ("Average Entropy", self.entropy(results["static"]["pe_sections"]))
            avgentropy = round(self.entropy(results["static"]["pe_sections"]), 4)

            csv_results += str(len(behavior)) + "," + str(len(dropped)) + "," + str(len(hosts)) + "," + str(avgentropy) + "," + classification+","+results["target"]["file"]["name"]
            print(csv_results)
            report = codecs.open(os.path.join(cwd("storage", "analyses"), "worms.data"), "a", "utf-8")
            report.write(csv_results + "\n")
            report.close()
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate CSV file: %s" % e)

    def entropy(self, pe_sections):
        sectionslen = len(str(pe_sections))
        entropies = []
        totalsize = sum(int(section["size_of_data"], 16) for section in pe_sections)
        return sum(section["entropy"]*int(section["size_of_data"],16)/totalsize for section in pe_sections)
