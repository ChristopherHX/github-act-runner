package protocol

import (
	"context"
	"net/url"
	"path"
)

type ServiceDefinition struct {
	ServiceType       string
	Identifier        string
	DisplayName       string
	RelativeToSetting string
	RelativePath      string
	Description       string
	ServiceOwner      string
	ResourceVersion   int
}

type LocationServiceData struct {
	ServiceDefinitions []ServiceDefinition
}

type ConnectionData struct {
	LocationServiceData LocationServiceData
}

func (vssConnection *VssConnection) GetConnectionData() *ConnectionData {
	url, err := url.Parse(vssConnection.TenantUrl)
	if err != nil {
		return nil
	}
	url.Path = path.Join(url.Path, "_apis/connectionData")
	q := url.Query()
	q.Add("connectOptions", "1")
	q.Add("lastChangeId", "-1")
	q.Add("lastChangeId64", "-1")
	url.RawQuery = q.Encode()
	connectionData := &ConnectionData{}
	err = vssConnection.RequestWithContext2(context.Background(), "GET", url.String(), "1.0", nil, connectionData)
	if err != nil {
		return nil
	}
	return connectionData
}

func (connectionData *ConnectionData) GetServiceDefinition(id string) *ServiceDefinition {
	for i := 0; i < len(connectionData.LocationServiceData.ServiceDefinitions); i++ {
		if connectionData.LocationServiceData.ServiceDefinitions[i].Identifier == id {
			return &connectionData.LocationServiceData.ServiceDefinitions[i]
		}
	}
	return nil
}
