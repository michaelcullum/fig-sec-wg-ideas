## FriendsOfPHP Security Advisories

* The file is in the YAML format and **must** contain the following entries
(have a look at existing entries for examples):

  * `title`:     A text that describes the security issue in a few words;

  * `link`:      A link to the official security issue announcement (HTTPS
    links are preferred over HTTP ones);

  * `reference`: A unique reference to identify the software (the only
    supported scheme is `composer://` followed by the Composer identifier);

  * `branches`: A hash of affected branches, where the name is the branch
    name (like `2.0.x`), and the value is a hash with the following
    entries:

      * `time`: The date and time in UTC when the security issue was fixed or null if the
        issue is not fixed yet (most of the time, the date of the **merge**
        commit that fixed the issue in the following format `2012-08-27
        19:17:44`) -- this information must be as accurate as possible as it
        is used to determine if a project is affected or not;

      * `versions`: An array of constraints describing affected versions
        for this branch (this is the same format as the one used for
        Composer -- `['>=2.0.0', '<2.0.17']`).

* If you have a CVE identifier, add it under the `cve` key.

e.g.
```yaml
title:     "CVE-2018-19790: Open Redirect Vulnerability on login"
link:      https://symfony.com/cve-2018-19790
cve:       CVE-2018-19790
branches:
    2.7.x:
        time:     2018-11-06 11:52:00
        versions: ['>=2.7.38', '<2.7.50']
    2.8.x:
        time:     2018-11-06 11:52:00
        versions: ['>=2.8.0', '<2.8.49']
    3.0.x:
        time:     2018-11-06 11:52:00
        versions: ['>=3.0.0', '<3.1.0']
    3.1.x:
        time:     2018-11-06 11:52:00
        versions: ['>=3.1.0', '<3.2.0']
    3.2.x:
        time:     2018-11-06 11:52:00
        versions: ['>=3.2.0', '<3.3.0']
    3.3.x:
        time:     2018-11-06 11:52:00
        versions: ['>=3.3.0', '<3.4.0']
    3.4.x:
        time:     2018-11-06 11:52:00
        versions: ['>=3.4.0', '<3.4.20']
    4.0.x:
        time:     2018-11-06 11:52:00
        versions: ['>=4.0.0', '<4.0.15']
    4.1.x:
        time:     2018-11-06 11:52:00
        versions: ['>=4.1.0', '<4.1.9']
    4.2.x:
        time:     2018-11-06 11:52:00
        versions: ['>=4.2.0', '<4.2.1']
reference: composer://symfony/symfony
```

## Common Vulnerability Reporting Framework (CVRF)

https://www.icasi.org/the-common-vulnerability-reporting-framework-cvrf-v1-1/
http://docs.oasis-open.org/csaf/csaf-cvrf/v1.2/csaf-cvrf-v1.2.html
https://www.icasi.org/cvrf/


XML-like:

```xml
<?xml version="1.0" encoding="utf-8"?>
<cvrfdoc xmlns:cpe="http://cpe.mitre.org/language/2.0"
  xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
  xmlns:cvrf-common="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/common"
  xmlns:cvssv2="http://scap.nist.gov/schema/cvss-v2/1.0"
  xmlns:cvssv3="https://www.first.org/cvss/cvss-v3.0.xsd"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:prod="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/1.0"
  xmlns:sch="http://purl.oclc.org/dsdl/schematron"
  xmlns:vuln="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln"
  xmlns:xsi=http://www.w3.org/2001/XMLSchema-instance
  xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
  >
  <!-- Document wide context information -->
  <DocumentTitle xml:lang="en">Red Hat Security Advisory: python-oslo-middleware security update</DocumentTitle>
  <DocumentType>Security Advisory</DocumentType>
  <DocumentPublisher Type="Vendor">
    <ContactDetails>secalert@redhat.com</ContactDetails>
    <IssuingAuthority>Red Hat Product Security</IssuingAuthority>
  </DocumentPublisher>
  <DocumentTracking>
    <Identification>
      <ID>RHSA-2017:0435</ID>
    </Identification>
    <Status>Final</Status>
    <Version>1</Version>
    <RevisionHistory>
      <Revision>
        <Number>1</Number>
        <Date>2017-03-02T21:13:00Z</Date>
        <Description>Current version</Description>
      </Revision>
    </RevisionHistory>
    <InitialReleaseDate>2017-03-02T21:13:00Z</InitialReleaseDate>
    <CurrentReleaseDate>2017-03-02T21:13:00Z</CurrentReleaseDate>
    <Generator>
      <Engine>Red Hat rhsa-to-cvrf 2.0</Engine>
      <Date>2017-03-04T05:06:05Z</Date>
    </Generator>
  </DocumentTracking>
  <DocumentNotes>
    <Note Title="Topic" Type="Summary" Ordinal="1" xml:lang="en">
An update for python-oslo-middleware is now available for Red Hat OpenStack Platform 9.0 (Mitaka).

Red Hat Product Security has rated this update as having a security impact of Moderate. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.    </Note>
    <Note Title="Details" Type="General" Ordinal="2" xml:lang="en">
The OpenStack Oslo Middleware library provides components that can be injected into WSGI pipelines to intercept request and response flows. The base class can be enhanced with functionality like adding or updating HTTP headers, or to offer support for limiting size or connections.

Security Fix(es):

* An information-disclosure flaw was found in oslo.middleware. Software using the CatchError class could include sensitive values in a traceback's error message. System users could exploit this flaw to obtain sensitive information from OpenStack component error logs (for example, keystone tokens). (CVE-2017-2592)

Red Hat would like to thank the OpenStack project for reporting this issue. Upstream acknowledges Divya K Konoor (IBM) as the original reporter.    </Note>
    <Note Title="Terms of Use" Ordinal="3" Type="Legal Disclaimer" xml:lang="en">Please see https://www.redhat.com/footer/terms-of-use.html</Note>
  </DocumentNotes>
  <DocumentDistribution xml:lang="en">Copyright © 2017 Red Hat, Inc. All rights reserved.</DocumentDistribution>
  <AggregateSeverity Namespace="https://access.redhat.com/security/updates/classification/">Moderate</AggregateSeverity>
  <DocumentReferences>
    <Reference Type="Self">
      <URL>https://rhn.redhat.com/errata/RHSA-2017-0435.html</URL>
      <Description>https://rhn.redhat.com/errata/RHSA-2017-0435.html</Description>
    </Reference>
    <Reference>
      <URL>https://access.redhat.com/security/updates/classification/#moderate</URL>
      <Description>https://access.redhat.com/security/updates/classification/#moderate</Description>
    </Reference>
  </DocumentReferences>
  <!-- Product tree section -->
  <prod:ProductTree xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod">
    <Branch Type="Product Family" Name="Red Hat Enterprise Linux OpenStack Platform">
      <Branch Type="Product Name" Name="Red Hat OpenStack Platform 9.0">
        <FullProductName ProductID="7Server-RH7-RHOS-9.0">Red Hat OpenStack Platform 9.0</FullProductName>
      </Branch>
    </Branch>
    <Branch Type="Product Version" Name="python-oslo-middleware-3.7.0-2.el7ost">
      <FullProductName ProductID="python-oslo-middleware-3.7.0-2.el7ost">python-oslo-middleware-3.7.0-2.el7ost.src.rpm</prod:FullProductName>
    </Branch>
    <Relationship ProductReference="python-oslo-middleware-3.7.0-2.el7ost"
      RelationType="Default Component Of" RelatesToProductReference="7Server-RH7-RHOS-9.0">
      <FullProductName ProductID="7Server-RH7-RHOS-9.0:python-oslo-middleware-3.7.0-2.el7ost">python-oslo-middleware-3.7.0-2.el7ost as a component of Red Hat OpenStack Platform 9.0</FullProductName>
    </Relationship>
  </ProductTree>
  <!-- Vulnerability section -->
  <vuln:Vulnerability Ordinal="1" 
   xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln">
    <Notes>
      <Note Title="Vulnerability Description" Type="General" Ordinal="1" xml:lang="en">An information-disclosure flaw was found in oslo.middleware. Software using the CatchError class could include sensitive values in a traceback's error message. System users could exploit this flaw to obtain sensitive information from OpenStack component error logs (for example, keystone tokens). </Note>
    </Notes>
    <DiscoveryDate>2017-01-18T00:00:00Z</DiscoveryDate>
    <ReleaseDate>2017-01-26T00:00:00Z</ReleaseDate>
    <Involvements>
      <Involvement Party="Vendor" Status="Completed"/>
    </Involvements>
    <CVE>CVE-2017-2592</CVE>
    <ProductStatuses>
      <Status Type="Fixed">
        <ProductID>7Server-RH7-RHOS-9.0:python-oslo-middleware-3.7.0-2.el7ost</ProductID>
      </Status>
    </ProductStatuses>
    <Threats>
      <Threat Type="Impact">
        <Description>Moderate</Description>
      </Threat>
    </Threats>

 


    <Remediations>
      <Remediation Type="Vendor Fix">
        <Description xml:lang="en">
For details on how to apply this update, which includes the changes described in this advisory, refer to:

https://access.redhat.com/articles/11258    </Description>
        <URL>https://rhn.redhat.com/errata/RHSA-2017-0435.html</URL>
      </Remediation>
    </Remediations>
    <References>
      <Reference>
        <URL>https://access.redhat.com/security/cve/CVE-2017-2592</URL>
        <Description>CVE-2017-2592</vuln:Description>
      </Reference>
      <Reference>
        <URL>https://bugzilla.redhat.com/show_bug.cgi?id=1414698</URL>
        <Description>bz#1414698: CVE-2017-2592 python-oslo-middleware: CatchErrors leaks sensitive values into error logs</Description>
      </Reference>
    </References>
    <Acknowledgments>
      <Acknowledgment>
        <Description>Red Hat would like to thank the OpenStack project for reporting this issue. Upstream acknowledges Divya K Konoor (IBM) as the original reporter.</Description>
      </Acknowledgment>
    </Acknowledgments>
  </Vulnerability>
  <!-- No more elements to follow -->
</cvrfdoc>
```

## PSR-9 Historical

The disclosure format is based on Atom [1], which in turn is based on XML. It
leverages the "The Common Vulnerability Reporting Framework (CVRF) v1.1" [2].
Specifically it leverages its dictionary [3] as its base terminology.

The Atom extensions [4] allow a structured description of the vulnerability to
enable automated tools to determine if installed is likely affected by the
vulnerability. However human readability is considered highly important and as
such not the full CVRF is used.

Note that for each vulnerability only a single entry MUST be created. In case
any information changes the original file MUST be updated along with the last
update field.

Any disclosure uses ``entryType`` using the following tags from the Atom
namespace (required tags are labeled with "MUST"):

* title (short description of the vulnerability and affected versions, MUST)
* summary (description of the vulnerability)
* author (contact information, MUST)
* published (initial publication date, MUST)
* updated (date of the last update)
* link (to reference more information)
* id (project specific vulnerability id)

In addition the following tags are added:

* reported (initial report date)
* reportedBy (contact information for the persons or entity that initially reported the vulnerability)
* resolvedBy (contact information for the persons or entity that resolved the vulnerability)
* name (name of the product, MUST)
* cve (unique CVE ID)
* cwe (unique CWE ID)
* severity (low, medium high)
* affected (version(s) using composer syntax)
* status (open, in progress, disputed, completed, MUST)
* remediation (textual description for how to fix an affected system)
* remediationType (workaround, mitigation, vendor fix, none available, will not fix)
* remediationLink (URL to give additional information for remediation)


```xml
<?xml version="1.0" encoding="UTF-8"?>

<xs:schema
        xmlns:xs="http://www.w3.org/2001/XMLSchema"
        targetNamespace="http://www.php-fig.org/schemas/security-disclosure"
        xmlns:sd="http://www.php-fig.org/schemas/security-disclosure"
        xmlns:atom="http://www.w3.org/2005/Atom"
        elementFormDefault="qualified">

    <xs:element name="name" type="xs:string" />

    <xs:element name="cve" type="xs:string" />

    <xs:element name="cwe" type="xs:string" minOccurs="0" />

    <xs:element name="reported" type="atom:dateTimeType" minOccurs="0" maxOccurs="1" />

    <xs:element name="reportedBy" type="atom:personType" minOccurs="0" maxOccurs="unbounded" />

    <xs:element name="resolvedBy" type="atom:personType" minOccurs="0" maxOccurs="unbounded" />

    <xs:simpleType name="severity">
        <xs:restriction base="xs:string">
            <xs:enumeration value="low" />
            <xs:enumeration value="medium" />
            <xs:enumeration value="high" />
        </xs:restriction>
    </xs:simpleType>

    <xs:simpleType name="status">
        <xs:restriction base="xs:string">
            <xs:enumeration value="open" />
            <xs:enumeration value="in progress" />
            <xs:enumeration value="disputed" />
            <xs:enumeration value="completed" />
        </xs:restriction>
    </xs:simpleType>

    <xs:element name="remediation" type="sd:remediationType" minOccurs="0" maxOccurs="unbounded" />

    <xs:complexType name="remediationType">
        <xs:annotation>
            <xs:documentation>
                The PHP FIG security disclosure remediation construct is to be used to specify a specific remediation
                option for a specific vulnerability.
            </xs:documentation>
        </xs:annotation>
        <xs:choice maxOccurs="unbounded">
            <xs:element name="summary" type="xs:string" />

            <xs:element name="affected" type="xs:string" />

            <xs:simpleType name="type">
                <xs:restriction base="xs:string">
                    <xs:enumeration value="workaround" />
                    <xs:enumeration value="mitigation" />
                    <xs:enumeration value="none available" />
                    <xs:enumeration value="will not fix" />
                </xs:restriction>
            </xs:simpleType>

            <xs:element name="link" type="atom:linkType" minOccurs="0" maxOccurs="unbounded" />
        </xs:choice>
    </xs:complexType>

</xs:schema>
```
