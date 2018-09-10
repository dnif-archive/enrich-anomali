# Anomali    
  https://www.anomali.com/

### Overview
Anomali ThreatStream Integrator is the software for integrating your existing security infrastructure to 
Anomali's ThreatStream platform (in the cloud) or to the on-premise ThreatStream Appliance.  

ThreatStream Integrator connects to the ThreatStream platform or the ThreatStream Appliance and
pulls rich, cyber threat intelligence feeds into existing tools and infrastructure thus bringing real-time
intelligence into your existing security solutions to provide operational efficiency and relevancy to
current security technologies.  

It can output this data in many formats such as CSV, Syslog, JSON, SNORT, and Common Event Format (CEF), and can also directly integrate with security solutions in your network.

### PRE-REQUISITES to use  Anomali Integrator API and DNIF  
Outbound access required to clone the Anomali Integrator enrichment plugin 

| Protocol   | Source IP  | Source Port  | Direction	 | Destination Domain | Destination Port  |  
|:------------- |:-------------|:-------------|:-------------|:-------------|:-------------|  
| TCP | AD,A10 | Any | Egress	| github.com | 443 |


### Using the Anomali Integrator API with DNIF
 The  Anomali Integrator API is found on github at

https://github.com/dnif/enrich-anomali

#### Getting started with Anomali Integrator API

1. #####    Login to your AD, A10 containers  
   ACCESS DNIF CONTAINER VIA SSH : [Click To Know How](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. #####    Move to the ‘/dnif/<Deployment-key/enrichment_plugin’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/enrichment_plugin/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/enrich-anomali.git anomali
```
### API feed output structure
The output of the lookup call has the following structure (for the available data):

  | Fields        | Description  |
| ------------- |:-------------:|
| EvtType      | An Domain |
| EvtName      | The IOC      |
| IntelRef | Feed Name      |
| IntelRefURL | Feed URL    |
| ThreatType | DNIF Feed Identification Name |      
| ALClassification     |<ul> <li> Indicates whether an IOC is private or from a public feed and available publicly</li><li>Possible values: private,public</li> </ul>  |
| ALStatus    | <ul> <li> Current state of the indicator.</li><li>Possible values: active,inactive, falsepositive</li> </ul>  |
| ALSeverity      | <ul> <li> Criticality associated with the threat feed that supplied the indicator..</li><li>Possible values: active,inactive, falsepos</li> </ul>  |
| ALTags      | Additional comments and context associated with the indicator when it was imported from its original threat feed. |
| ALSource      | <ul><li>Source name associated withthe indicator.</li><li> The source field contains a string label that identifies the source of the indicator to ThreatStream </li></ul>  |
| ALModifiedTstamp      | Time stamp of when the indicator was last updated in ThreatStream. |
| ALMalType      | Information regarding a malware family, a CVE ID, or another attack or threat, associated with the indicator    |
| ALConfidence      | Risk score from 0 to 100, assigned by ThreatStream's predictive analytics technology to indicators   |

An example of API feed output
```
{'EvtType': 'DOMAIN',
'EvtName': u'facebook.webhop.me',
'AddFields':{
'IntelRef': ['ANOMALI'],
'IntelRefURL': [''],
'ThreatType': ['Suspicious Domain'],
'ALClassification': [u'private'],
'ALStatus': [u'active'], 
'ALSeverity': [u'medium'], 
'ALTags': [u'Suspicious-Domain,Dynamic-DNS,FACEBOOK'], 
'ALSource': [u'Anomali Labs Suspicious Domains - Dynamic DNS'],
'ALModifiedTstamp': [u'2018-09-03T19:06:36'],
'ALMalType': [u'Suspicious-Domain'],
'ALConfidence': [93]}}
```
