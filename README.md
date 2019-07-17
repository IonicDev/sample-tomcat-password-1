# Ionic Java SDK Sample Application / Tomcat SSL Keystore Password

The [Ionic SDK](https://dev.ionic.com/) provides an easy-to-use interface to the
[Ionic Platform](https://www.ionic.com/). In particular, the Ionic SDK exposes functions to perform Key Management
and Data Encryption.

The [Apache Tomcat](http://tomcat.apache.org/) web container application includes support for TLS (SSL) client 
connections on one or more dedicated ports.  To enable this feature, it is necessary to specify a 
[TLS keystore](https://en.wikipedia.org/wiki/Java_Secure_Socket_Extension) for each TLS port.  Keystores are typically 
password-protected for security reasons; the keystore section of the Tomcat configuration usually includes this 
password.

When possible, it is desirable to secure this password, to prevent its disclosure in the event of system 
compromise.  There are a few general-purpose strategies for providing passwords to applications at startup:

- Password is entered by hand in the process console at startup.
- Application configuration files contain password; files are secured via operating system file permissions.

In the first case, manual intervention prevents the ability to automate process restarts.  In the second case, 
exploitation of operating system vulnerabilities can expose the content of secured files.

The Ionic platform can be used in situations like this to provide an additional layer of protection to passwords in 
configuration files.  [Ionic chunk ciphers](https://dev.ionic.com/sdk/formats/chunk) can transform a passphrase to its 
encrypted representation, which can then be stored in the configuration 
file.  [Ionic policy controls](https://dev.ionic.com/api/policies) can then allow the release of the encryption key 
only to the device authorized to access the encrypted data.

## Tomcat Configuration *PropertySource*
The Tomcat software includes an extension point that allows users to modify the default loading of configuration 
variables.  The extension point is documented [here](https://tomcat.apache.org/tomcat-9.0-doc/config/systemprops.html).

This code sample will make use of the Tomcat extension point to allow for storage of arbitrary Ionic-protected 
configuration values in the Tomcat configuration.  These settings will be seamlessly decrypted on access by the Ionic 
configuration accessor.  The code sample will describe how this facility can be used to protect the Tomcat TLS keystore 
password.

## Prerequisites

- physical machine (or virtual machine) with the following software installed
  - Java Runtime Environment 7+
  - Apache Maven (Java software project management tool)
- a valid, password-protected PKCS12 or JKS keystore
- a valid [Ionic Secure Enrollment Profile](https://dev.ionic.com/getting-started/create-ionic-profile) (a plaintext
json file containing access token data), in a file named *ionic.sep.plaintext.json*

The Ionic Secure Enrollment Profile contains data defining the Ionic server to use, as well as data to identify the 
client making the requests.  More details can be found [here](https://dev.ionic.com/platform/enrollment).

The instructions for obtaining an 
[Ionic Secure Enrollment Profile](https://dev.ionic.com/getting-started/create-ionic-profile) describe the 
`ionic-profiles` command line tool that is used for this purpose (given an active Ionic account).  Consult the web 
documentation for all of the options available in this tool.

During the walk-through of this demo, you will download the following:
- version 9.0.19 of Apache Tomcat (Java web container application)
- the git repository associated with this sample application

## Project Content

Let's take a brief tour of the content of this demo project.

**[javasdk-sample-tomcat/pom.xml]**

Here we declare the dependencies for the project.
```
    <dependency>
        <groupId>com.ionic</groupId>
        <artifactId>ionic-sdk</artifactId>
        <version>2.5.0</version>
    </dependency>
    <dependency>
        <groupId>org.apache.tomcat</groupId>
        <artifactId>tomcat-util</artifactId>
        <version>9.0.19</version>
    </dependency>
```

**[javasdk-sample-tomcat/src/main/java/com/ionic/sdk/addon/tomcat/util/PropertySource.java]**

This class extends the Tomcat interface 
[PropertySource](https://tomcat.apache.org/tomcat-9.0-doc/api/org/apache/tomcat/util/IntrospectionUtils.PropertySource.html).  Tomcat 
provides this interface to allow the interpretation of values in its configuration via extension code.  Running the 
Maven script will produce a Java JAR library that will be incorporated into a Tomcat installation.  When Tomcat is 
started, code in this class will be executed by Tomcat each time `${parameter}` denoted parameters are 
encountered in its configuration.  This class 
analyzes each value to determine whether it is Ionic-protected.  Any protected values will be decrypted in memory, and 
the plaintext values will be passed along to the application.

This class can also be used to generate the Ionic-protected ciphertext for the value.  To do this, set the value like 
this: `${IonicEncrypt.mysslkeystorepassword}`.  On Tomcat startup, when this configuration value is read, the 
*PropertySource* implementation will log the Ionic-protected representation of `mysslkeystorepassword`, and then 
pass `mysslkeystorepassword` back to Tomcat to be used.

## Sample Application Walk-through

1. Clone git demo repository into an empty folder on your filesystem.
    ```shell
    git clone https://github.com/IonicDev/sample-tomcat-password-1.git
    ```

1. Navigate to the root folder of the *sample-tomcat-password-1* repository.  Run the following command to assemble the
demo webapp:
    ```shell
    mvn clean package
    ```

1. Download the [Tomcat image](https://tomcat.apache.org/download-90.cgi).

1. Inflate image into an empty folder on your filesystem.

1. Copy your password-protected PKCS12 or JKS keystore into the folder **[tomcat/conf]**.

1. Edit the file **[tomcat/conf/server.xml]**.  Find the (commented out) configuration section containing the 
declaration for SSL on port 8443.
    ```xml
    <!--
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true">
        <SSLHostConfig>
            <Certificate certificateKeystoreFile="conf/localhost-rsa.jks"
                         type="RSA" />
        </SSLHostConfig>
    </Connector>
    -->
    ```

    Uncomment and populate this configuration section following the example below.  Replace the value 
    `mysslkeystorepassword` with your actual password.
    ```xml
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
        maxThreads="150" SSLEnabled="true"
        scheme="https" secure="true" keystoreFile="conf/server.pkcs12" sslProtocol="TLS"
        keystorePass="${IonicEncrypt.mysslkeystorepassword}"
        />
    ```

    The `keystoreFile` attribute should reference the name of your keystore (for example: 'server.pkcs12').
    The value of the attribute `keystorePass` should be wrapped with the characters 
    **`${`** at the beginning and 
    **`}`** at the end.  These are interpreted by Tomcat as an instruction to resolve the wrapped content, thus 
    triggering the *PropertySource* sample code.

    When Tomcat encounters the value `${IonicEncrypt.mysslkeystorepassword}`, it will unwrap the data and pass the
    value `IonicEncrypt.mysslkeystorepassword` along to the custom *PropertySource*.  This code interprets any 
    value beginning with `IonicEncrypt.` as an instruction to encrypt the rest of the value, and log the 
    result.  The value `mysslkeystorepassword` will be passed back to Tomcat, allowing the keystore to be unlocked.

1. Add the file containing your Ionic Secure Enrollment Profile text into the *conf* folder of the new Tomcat image 
**[tomcat/conf/ionic.sep.plaintext.json]**.

1. Copy the code sample library file **[javasdk-sample-tomcat/target/ionic-sdk-tomcat-property-0.0.1.jar]** 
into **[tomcat/lib]**.

1. Copy all files in **[javasdk-sample-tomcat/target/lib]** into **[tomcat/lib]**.  There should be two files:
    - ionic-sdk-2.5.0.jar
    - javax.json-1.0.4.jar

1. Edit **[tomcat/bin/catalina.bat]**.  Find the script code at the label **`:doRun`**.  Insert a line defining the 
property that enables the Ionic sample *PropertySource*.
    
    before:
    ```script
    :doRun
    shift
    if not ""%1"" == ""-security"" goto execCmd
    shift
    echo Using Security Manager
    set "SECURITY_POLICY_FILE=%CATALINA_BASE%\conf\catalina.policy"
    goto execCmd
    ```

    after:
    ```script
    :doRun
    shift
    set CATALINA_OPTS=-Dorg.apache.tomcat.util.digester.PROPERTY_SOURCE=com.ionic.sdk.addon.tomcat.util.PropertySource
    if not ""%1"" == ""-security"" goto execCmd
    shift
    echo Using Security Manager
    set "SECURITY_POLICY_FILE=%CATALINA_BASE%\conf\catalina.policy"
    goto execCmd
    ```

1. Navigate to the root folder of the Tomcat instance.  Run the following command in a console to start Tomcat 
    (Ctrl+C to stop):
    ```shell
    bin\catalina.bat run
    ```
    
    If the SSL keystore password was correct, the server should start normally.  

1. Enter the (Ctrl+C) key sequence to stop the Tomcat process.

1. Examine the console output for the Tomcat startup.  You should find a line like the following:
    ```text
    INFO [main] com.ionic.sdk.addon.tomcat.util.PropertySource.getProperty IonicEncrypt. = ~!3!D7GHDudu-Z8!B+RTDJLPjs/ICOqlx44P6gwnnfnsuuwtzHwVn+cgIi4ABgdg!
    ```

    The portion of the line after `IonicEncrypt. = ` is the Ionic chunk cipher representation of the keystore 
    password.
    
1. Edit the file **[tomcat/conf/server.xml]** again.  Find the configuration section containing the 
declaration for SSL on port 8443.

    Modify the content, replacing the value 
    `${IonicEncrypt.mysslkeystorepassword}` with the chunk cipher representation of the password.
    ```xml
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
        maxThreads="150" SSLEnabled="true"
        scheme="https" secure="true" keystoreFile="conf/server.pkcs12" sslProtocol="TLS"
        keystorePass="${~!3!D7GHDudu-Z8!B+RTDJLPjs/ICOqlx44P6gwnnfnsuuwtzHwVn+cgIi4ABgdg!}"
        />
    ```
    Don't forget to wrap the chunk cipher value with the characters 
    **`${`** at the beginning and 
    **`}`** at the end.  

1. Run the following command in a console to start Tomcat again:
    ```shell
    bin\catalina.bat run
    ```
    
    The server should start normally, unlocking the SSL keystore with the Ionic decrypted password.

## Conclusion

In this sample, the Tomcat *PropertySource* facility was used to protect the SSL keystore password in the configuration 
with Ionic encryption.  Ionic server policy may be used to restrict access to the decryption key.

Other software applications have similar facilities to guard sensitive content in configuration files.  For example, 
the Apache HTTPD web server uses the `SSLPassPhraseDialog` facility, described 
[here](https://httpd.apache.org/docs/2.4/ssl/ssl_faq.html#removepassphrase).

Ionic's platform is powerful and flexible enough to be broadly applicable to the data protection needs of modern
organizations.
