# audit_log
Create alerts based on suspicious activity provided

## Testing
 
Update config.ini file to point to the test csv file,  takehome.csv.  test_auditreader.py and test_detectory.py are configured for unittesting.


## Config.ini

Prior to building docker, review the audit log to determine what the attackers did on the system. Once malicious activity has been observed, update the config.ini file and input the commands you want to search for.

> [behaviours]

>username=username <--Set the username you want to follow

> cmds=curl|cp|chmod|.*bash.*|wget|cat <--Seperate your commands using the pipe symbol (|)

## Docker Setup

> docker build -t audit_log .

## Docker Run

Docker Run will 
> docker run audit_log

The alerts are sent to STDOUT.  To review the alerts once more we can review the docker logs of the container.

Copy the Container ID and paste it in the docker logs command
> docker ps -a
>
> docker logs containerID

