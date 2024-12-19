from burp import IBurpExtender, IHttpListener, IScanIssue
import re

# made by Ahmed Abd-elazem
# detect reflected headers value in the response

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("reflected-headers detector")
        callbacks.registerHttpListener(self)
        print("[INFO] Header Reflection Checker loaded and running!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Analyze responses only
        if messageIsRequest:
            return

        try:
            request = messageInfo.getRequest()
            response = messageInfo.getResponse()
            if not response:
                # print("[DEBUG] No response available for processing.")
                return

            analyzedRequest = self._helpers.analyzeRequest(request)
            analyzedResponse = self._helpers.analyzeResponse(response)

            # Extract headers and response body
            headers = analyzedRequest.getHeaders()
            bodyOffset = analyzedResponse.getBodyOffset()
            responseBody = response[bodyOffset:].tostring()

            # Check for header value reflections in the response body, excluding "Host"
            reflection_detected = False
            for header in headers:
                if ":" in header:
                    key, value = header.split(":", 1)
                    key = key.strip()
                    value = value.strip()


                    # Skip the Host header
                    if key.lower() in ["host", "Sec-Fetch-Dest", "Sec-Fetch-Site", "Accept"]:
                        print("[+]not logged header: "+key)
                        continue

                    # Skip if the value matches any of the specified strings
                    if value.lower() in ["script", "no-cors", "style", "true"]:
                        print("[+]not logged value: "+value)
                        continue

                    # Skip if the value is less than 3 characters
                    if len(value) < 3:
                        continue


                    # Check if the value is reflected in the response body
                    if value and re.search(re.escape(value), responseBody, re.IGNORECASE):
                        print("[DEBUG] Reflection detected! Header: {}, Value: {}".format(key, value))
                        reflection_detected = True
                        self.add_issue(messageInfo, key, value)

            if not reflection_detected:
                pass
                # print("[DEBUG] No reflections detected in the response.")

        except Exception as e:
            print("[ERROR] Exception occurred: {}".format(e))

    def add_issue(self, messageInfo, key, value):
        try:
            issue = CustomScanIssue(
                httpService=messageInfo.getHttpService(),
                url=self._helpers.analyzeRequest(messageInfo).getUrl(),
                requestResponse=messageInfo,
                name="Header Reflection Detected",
                detail="The value '{}' of the header '{}' was reflected in the response.".format(value,key),
                severity="Low"
            )
            self._callbacks.addScanIssue(issue)
            print("[INFO] Issue added to Site map: Header Reflection Detected for header '{}'.".format(key))
        except Exception as e:
            print("[ERROR] Failed to add issue: {}".format(e))

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, requestResponse, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return [self._requestResponse]

    def getHttpService(self):
        return self._httpService

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0  # Custom issue type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Reflected headers may indicate a vulnerability, such as Cross-Site Scripting (XSS) or sensitive information disclosure or caching issues."

    def getRemediationBackground(self):
        return "Sanitize all user-supplied input that is reflected in server responses to mitigate potential security risks."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None
