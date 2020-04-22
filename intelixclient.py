import requests
import json
import base64
import uuid
import os.path



class client:
    def __init__(self,clientID,clientSecret):
        #authenticate to the service using the provided clientID and secret 
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.authToken = self.clientID + ":" + self.clientSecret
        auth_headers = {'Authorization' : "Basic " + base64.b64encode(self.authToken.encode('UTF-8')).decode('ascii'),'Content-Type' : 'application/x-www-form-urlencoded'}
        authURI = "https://api.labs.sophos.com/oauth2/token"
        try:
            r = requests.post(authURI,headers=auth_headers, data="grant_type=client_credentials")
            response = json.loads(r.text)
            #if the authentication is successful, set the access token to be used in future requests
            self.access_token = response.get('access_token')
        except requests.exceptions.HTTPError as err:
            print(err)
    
    def file_lookup(self,fileHash):
        #perform a file reputation lookup by using a sha256 hash
        self.fileHash = fileHash
        lookup_uri = "https://de.api.labs.sophos.com/lookup/files/v1/" + self.fileHash
        correlationId = str(uuid.uuid1())
        request_headers = {'Authorization' : self.access_token,'X-Correlation-ID' : correlationId}
        try:
            r = requests.get(lookup_uri,headers=request_headers)
            response = json.loads(r.text)
            #assign the various values from the response
            self.correlationId = response.get('correlationId')
            self.requestId = response.get('requestId')
            self.ttl = response.get('ttl')
            self.reputationScore = response.get('reputationScore')
            #use the reputation score to determine the classification of the file based off the bands provided in the API docs
            if (self.reputationScore <= 19):
                self.classification = "Malware"
            elif (self.reputationScore > 19 and self.reputationScore <= 29):
                self.classification = "PUA"
            elif (self.reputationScore > 29 and self.reputationScore <= 69):
                self.classification = "Unknown/suspicious"
            elif (self.reputationScore > 69 and self.reputationScore <= 100):
                self.classification = "Known Good"
            else:
                self.classification = "error"
        except requests.exceptions.HTTPError as err:
            print(err)
    
    def url_lookup(self,url):
        #perform a reputation lookup based on a provided URL
        self.url = url
        lookup_uri = "https://de.api.labs.sophos.com/lookup/urls/v1/" + self.url
        correlationId = str(uuid.uuid1())
        request_headers = {'Authorization' : self.access_token,'X-Correlation-ID' : correlationId}
        try:
            r = requests.get(lookup_uri,headers=request_headers)
            response = json.loads(r.text)
            #assign values from the response
            self.correlationId = response.get('correlationId')
            self.requestId = response.get('requestId')
            self.productivityCategory = response.get('productivityCategory')
            self.securityCategory = response.get('securityCategory')
            self.riskLevel = response.get('riskLevel')
        except requests.exceptions.HTTPError as err:
            print(err)
 
    def ip_lookup(self,ipaddr):
        #perform a reputation lookup based on a provided ip address
        self.ipaddr = ipaddr
        lookup_uri = "https://de.api.labs.sophos.com/lookup/ips/v1/" + self.ipaddr
        correlationId = str(uuid.uuid1())
        request_headers = {'Authorization' : self.access_token,'X-Correlation-ID' : correlationId}
        try:
            r = requests.get(lookup_uri,headers=request_headers)
            response = json.loads(r.text)
            #assign values from the response
            self.correlationId = response.get('correlationId')
            self.requestId = response.get('requestID')
            self.category = response.get('category')
            self.ttl = response.get('ttl')
        except requests.exceptions.HTTPError as err:
            print(err)
        
    def file_report_by_hash(self,hash,analysisType):
        #retrieve an analysis report from a provided sha256 hash, can be for a dynamic or static analysis depending on the passed analysisType parameter
        if not (analysisType == 'static' or analysisType == 'dynamic'): raise Exception('analysisType Must be static or dynamic')
        lookup_uri = f"https://de.api.labs.sophos.com/analysis/file/{analysisType}/v1/reports?sha256=" + hash
        correlationId = str(uuid.uuid1())
        request_headers = {'Authorization' : self.access_token,'X-Correlation-ID' : correlationId}
        try:
            r = requests.get(lookup_uri,headers=request_headers)
            response = json.loads(r.text)
            #assign values from the response
            self.report = response.get('report')
            self.jobStatus = response.get('jobStatus')
            self.jobId = response.get('jobId')
        except requests.exceptions.HTTPError as err:
            print(err)

    def file_report_by_jobid(self,jobId,analysisType):
        #retrieve an analysis report from a provided job ID, can be for a dynamic or static analysis depending on the passed analysisType parameter.  The job ID is retrieved from a submission job
        if not (analysisType == 'static' or analysisType == 'dynamic'): raise Exception('analysisType Must be static or dynamic')
        lookup_uri = f"https://de.api.labs.sophos.com/analysis/file/{analysisType}/v1/reports/" + jobId
        correlationId = str(uuid.uuid1())
        request_headers = {'Authorization' : self.access_token,'X-Correlation-ID' : correlationId}
        try:
            r = requests.get(lookup_uri,headers=request_headers)
            response = json.loads(r.text)
            #assign values from the response
            self.report = response.get('report')
            self.jobStatus = response.get('jobStatus')
            self.jobId = response.get('jobId')
        except requests.exceptions.HTTPError as err:
            print(err)
    
    def submit_file(self,filePath,analysisType):
        #submit a file for analysis, the analysis can either dynamic or static analysis depending on the passed analysisType parameter.
        if not (analysisType == 'static' or analysisType == 'dynamic'): raise Exception('analysisType Must be static or dynamic')
        submission_uri = f"https://de.api.labs.sophos.com/analysis/file/{analysisType}/v1"
        correlationId = str(uuid.uuid1())
        request_headers = {'Authorization' : self.access_token,'X-Correlation-ID' : correlationId}
        try:
            #open the file to upload
            uploadFile = open(filePath, 'rb')
            files = {'file': uploadFile}
            try:
                r = requests.post(submission_uri, headers=request_headers, files=files)
                r.raise_for_status()
                response = json.loads(r.text)
                #assign values from response
                self.jobStatus = response.get('jobStatus')
                self.jobId = response.get('jobId')
                #if the call receives success for the job status, the report is already available and so is retrieved from the response
                if self.jobStatus == 'SUCCESS':
                    self.report = response.get('report')
            except requests.exceptions.HTTPError as err:
                print(err)
        except IOError:
            print("Could not read the file: " + filePath)
