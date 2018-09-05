Getting Started for Open Enclave (OE) application developers
========================================================

Download and Install OE SDK package
----------------------------------------------
 
 - Download the latest release package from  [OE SDK package releases](https://github.com/Microsoft/openenclave/releases)
 
   Let's say, the downloaded OE SDK package is openenclave-x.x.x-Linux.deb

 - Install it to your target Linux system with the following dpkg command

       sudo dpkg -i openenclave-x.x.x-Linux.deb

   On a successful OE SDK installation, you will have the following components installed under the installation target directory: install_prefix (The default installtion path for a release package is /opt/openenclave)


| Path                                     | Description                     |
|------------------------------------------|---------------------------------|
| /opt/openenclave/bin                     | developer tools such as oe-gdb for debugging and oesign for signing your enclaves |
| /opt/openenclave/include/openenclave     | OE runtime headers for use in your enclave (enclave.h) and its host (host.h)                        |
| /opt/openenclaveinclude/libc            | c library headers for use inside the enclave. See the API Reference section for supported functions|
| /opt/openenclave/include/libcxx          | c++ library headers for use inside the enclave. See the API Reference section for supported functions|
| /opt/openenclave/include/mbedtls         | mbedtls library headers for use inside the enclave. See the API Reference section for supported function|
| /opt/openenclave/lib/openenclave/enclave | libraries for linking into the enclave, including the libc, libcxx and mbedtls libraries for OE|
| /opt/openenclave/lib/openenclave/host    | library for linking into the host process of the enclave|
| /opt/openenclave/lib/openenclave/debugger| libraries used by the gdb plug-in for debugging enclaves|
| /opt/openenclave/share/doc/openenclave   | OE API documentation in HTML format, which can be browsed starting with index.html. It is consistent with the version of the SDK installed|
| /opt/openenclave/share/openenclave/samples  | all OE samples|

  
OE Samples
-------------------------------

   The default install directory for an Open Enclave SDK installationis /opt/openenclave. On a successful installation, you can find all the samples under 
   
       /opt/openenclave/share/openenclave/samples
  
  See [OE samples](sampedocs/README.md) for details
    
SDK API Reference
-------------------------------

  [SDK API Reference](APIsAvaiableToEnclave.md)

