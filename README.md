
An attempt to generate music from different packet flows running through a network adapter. 

Make sure and install libpcap-dev first.

Then run: 

```
go get ./...
go build
sudo ./musical-packets -i <interface>
```