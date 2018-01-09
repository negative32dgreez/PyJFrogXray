import requests
from requests.auth import HTTPBasicAuth
import json
import csv

class xray_jfrog_api:
    
    def __init__(self, baseuri, username, password):
        self.baseuri = baseuri
        self.auth = HTTPBasicAuth(username, password)
        self.severity = None
        self.listOfIssues = []

    #direction = desc, asc
    #severity = Critical, Major, Minor, Unknown
    def getComponents(self, direction="desc", num_of_rows = "20", order_by= "last_updated", page_num="1",
                      severity=None, component_type=None):

        if severity:
            self.severity = "Critical"
        else:
            self.severity = None
        myURL = self.baseuri +"/ui/component/paginatedsearch"
        querystring = {}
        querystring.update({"direction":direction})          
        querystring.update({"num_of_rows":num_of_rows})
        querystring.update({"order_by":order_by})
        querystring.update({"page_num":page_num})

        payload = {}
        if severity:
            payload.update({"severity":severity})
        if component_type:
            payload.update({"component_type":component_type})

        
        headers = {
            'content-type': "application/json;charset=UTF-8",
            'accept': "application/json, text/plain, */*",
            }
        response = requests.request("POST", myURL, data=json.dumps(payload),auth=self.auth, headers=headers, params=querystring)

        return response.json()

    def componentsToCSV(self, data):
       data = data.get('data')
       with open('DATA.csv', 'w') as csvfile:
           myWriter = csv.writer(csvfile, lineterminator='\n')
           myWriter.writerow(['pkg_name', 'top_severity', 'pkg_id', 'num_issues', 'last_updated', 'latest_version', 'myType'])
           for oneData in data:
               last_updated = oneData.get('last_updated', "")
               pkg_type = oneData.get('pkg_type', "")
               latest_version = oneData.get('latest_version', "")
               num_issues = oneData.get('num_issues', "")
               pkg_id = oneData.get('pkg_id', "")
               myType = oneData.get('type', "")
               top_severity = oneData.get('top_severity', "")
               pkg_name = oneData.get('pkg_name',"")
               
               myWriter.writerow([pkg_name, top_severity, pkg_id, num_issues, last_updated, latest_version, myType])

    def getIssues(self, latest_version, pkg_id):


        myURL = self.baseuri +"/ui/component/details/paginatedIssues"


        querystring = {}
        querystring.update({"direction":"asc"})          
        querystring.update({"num_of_rows":"1000"})
        querystring.update({"order_by":"severity"})
        querystring.update({"page_num":"1"})


        
        payload = {}
        payload.update({"version":latest_version})
        payload.update({"package_id":pkg_id})
        headers = {
            'content-type': "application/json;charset=UTF-8",
            'accept': "application/json, text/plain, */*",
            }
        response = requests.request("POST", myURL, data=json.dumps(payload),auth=self.auth, headers=headers, params=querystring)
        return response.json()


    def getImpactPath(self, vulnerability_id,component_id ):
        myURL = self.baseuri +"/ui/impactPath"
        
        payload = {}
        payload.update({"component_id":component_id})
        payload.update({"vulnerability_id":vulnerability_id})
        headers = {
            'content-type': "application/json;charset=UTF-8",
            'accept': "application/json, text/plain, */*",
            }
        response = requests.request("POST", myURL, data=json.dumps(payload),auth=self.auth, headers=headers)

        impactData =  response.json()
        impactPath = impactData.get("impact_paths")
        oneImpact = impactPath[0]
        myParts = oneImpact.get("parts")

        #grabbing the affected Verson
        affectedVersionList = []
        for parts in myParts:
            affectedVersion = parts.get("component_id")
            affectedVersionList.append(affectedVersion)

        return affectedVersionList



    def getIssueDetails(self,component_id,source_name, vulnerability_id):
        myURL = self.baseuri +"/ui/component/issueDetails"
        
        querystring = {}
        querystring.update({"no_spinner":"true"})          

        payload = {}
        payload.update({"component_id":component_id})
        payload.update({"source_name":source_name})
        payload.update({"vulnerability_id":vulnerability_id})
        
        headers = {
            'content-type': "application/json;charset=UTF-8",
            'accept': "application/json, text/plain, */*",
            }
        response = requests.request("POST", myURL, data=json.dumps(payload),auth=self.auth, headers=headers)
        issueData =  response.json()
        return issueData

        
    def componentsToIssues(self, data, severity="Critical"):
       data = data.get('data')
       for oneData in data:
           latest_version = oneData.get('latest_version', "")
           pkg_id = oneData.get('pkg_id', "")

           if pkg_id == "docker://bad-dockerfile":

            
               dataIssues = self.getIssues(latest_version, pkg_id)
               dataIssues = dataIssues.get('data')

               myListOfComponents = []
               for impactpaths in dataIssues:
                   mySeverity = impactpaths.get("severity")

                   
                   if mySeverity == severity: ##critical
                       vulnerability_id = impactpaths.get("id")
                       component_id = pkg_id+":"+ latest_version
                       myComponent = impactpaths.get("component")
                       
                       
                       
                        #check if component already exist to remove deduplication
                       if myComponent in myListOfComponents:
                           pass
                       else:
                           #grab aall the affected version
                           affectedVersionList = self.getImpactPath(vulnerability_id, component_id)
                           myListOfComponents.append(myComponent)
                    

                           #get list of location?

                           #get cwe?
                           issueData = self.getIssueDetails(component_id,myComponent,vulnerability_id)

                           issueSummary = issueData.get("summary")
                           issueDescription = issueData.get("description")
                           issueCVE = issueData.get("cwe")
                           
                           self.listOfIssues.append({
                               "package":pkg_id,
                               "severity":mySeverity,
                               "component": myComponent,
                               "issueSummary": issueSummary,
                               "issueDescription":issueDescription,
                               "affectedVersionList":affectedVersionList,
                               "issueCVE":issueCVE
                               })
 
           
            
    def listOfIssuesToCsv(self):
        
       data = self.listOfIssues
       with open('DATA.csv', 'w') as csvfile:
           myWriter = csv.writer(csvfile, lineterminator='\n')
           #myWriter.writerow()
           for oneData in data:

               package = oneData.get('package', "")
               severity = oneData.get('severity', "")
               component = oneData.get('component', "")
               issueSummary = oneData.get('issueSummary', "")
               issueDescription = oneData.get('issueDescription', "")
               issueCVE = oneData.get('issueCVE', "")
               affectedVersionList = oneData.get('affectedVersionList', "")
               
               myWriter.writerow([package, severity, component,issueSummary,issueDescription,issueCVE, affectedVersionList])

               


if __name__ == "__main__":
    baseuri = "http://xray:8000"
    username = "user"
    password = "pass"
    d = xray_jfrog_api(baseuri,username,password)
    x = d.getComponents(num_of_rows="6",
                    severity="Critical",
                    component_type="packages")
    issuesData = d.componentsToIssues(x,severity="Critical")

    d.listOfIssuesToCsv()

