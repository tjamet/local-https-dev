package egoscale

import (
	"testing"
)

func TestResetSSHKeyForVirtualMachine(t *testing.T) {
	req := &ResetSSHKeyForVirtualMachine{}
	if req.APIName() != "resetSSHKeyForVirtualMachine" {
		t.Errorf("API call doesn't match")
	}
	_ = req.asyncResponse().(*ResetSSHKeyForVirtualMachineResponse)
}

func TestRegisterSSHKeyPair(t *testing.T) {
	req := &RegisterSSHKeyPair{}
	if req.APIName() != "registerSSHKeyPair" {
		t.Errorf("API call doesn't match")
	}
	_ = req.response().(*RegisterSSHKeyPairResponse)
}

func TestCreateSSHKeyPair(t *testing.T) {
	req := &CreateSSHKeyPair{}
	if req.APIName() != "createSSHKeyPair" {
		t.Errorf("API call doesn't match")
	}
	_ = req.response().(*CreateSSHKeyPairResponse)
}

func TestDeleteSSHKeyPair(t *testing.T) {
	req := &DeleteSSHKeyPair{}
	if req.APIName() != "deleteSSHKeyPair" {
		t.Errorf("API call doesn't match")
	}
	_ = req.response().(*booleanSyncResponse)
}

func TestListSSHKeyPairsResponse(t *testing.T) {
	req := &ListSSHKeyPairs{}
	if req.APIName() != "listSSHKeyPairs" {
		t.Errorf("API call doesn't match")
	}
	_ = req.response().(*ListSSHKeyPairsResponse)
}

func TestGetSSHKeyPair(t *testing.T) {
	ts := newServer(response{200, `
{"listsshkeypairsresponse": {
	"count": 1,
	"sshkeypair": [
		{
			"fingerprint": "07:97:32:04:80:23:b9:a2:a2:46:fe:ab:a6:4b:20:76",
			"name": "yoan@herp"
		}
	]
}}`})
	defer ts.Close()

	cs := NewClient(ts.URL, "KEY", "SECRET")
	ssh := &SSHKeyPair{
		Name: "yoan@herp",
	}
	if err := cs.Get(ssh); err != nil {
		t.Error(err)
	}

	if ssh.Fingerprint != "07:97:32:04:80:23:b9:a2:a2:46:fe:ab:a6:4b:20:76" {
		t.Errorf("Fingerprint doesn't match, got %v", ssh.Fingerprint)
	}
}

func TestGetSSHKeyPairToMany(t *testing.T) {
	ts := newServer(response{200, `
{"listsshkeypairsresponse": {
	"count": 2,
	"sshkeypair": [
		{
			"fingerprint": "07:97:32:04:80:23:b9:a2:a2:46:fe:ab:a6:4b:20:76",
			"name": "yoan@herp"
		},
		{
			"fingerprint": "9e:97:54:95:82:22:eb:f8:9b:4f:28:6f:c7:f5:58:83",
			"name": "yoan@derp"
		}
	]
}}`})
	defer ts.Close()

	cs := NewClient(ts.URL, "KEY", "SECRET")
	ssh := &SSHKeyPair{
		Name: "Hello",
	}
	if err := cs.Get(ssh); err == nil {
		t.Errorf("An error was expected")
	}
}

func TestListSSHKeyPairs(t *testing.T) {
	ts := newServer(response{200, `
{"listsshkeypairsresponse": {
	"count": 2,
	"sshkeypair": [
		{
			"fingerprint": "07:97:32:04:80:23:b9:a2:a2:46:fe:ab:a6:4b:20:76",
			"name": "yoan@herp"
		},
		{
			"fingerprint": "9e:97:54:95:82:22:eb:f8:9b:4f:28:6f:c7:f5:58:83",
			"name": "yoan@derp"
		}
	]
}}`})
	defer ts.Close()

	cs := NewClient(ts.URL, "KEY", "SECRET")
	ssh := &SSHKeyPair{}

	sshs, err := cs.List(ssh)
	if err != nil {
		t.Error(err)
	}

	if len(sshs) != 2 {
		t.Errorf("Expected two ssh keys, got %v", len(sshs))
	}
}

func TestGetSSHKeyPairNotFound(t *testing.T) {
	ts := newServer(response{200, `
{"listsshkeypairsresponse": {
	"count": 0,
	"sshkeypair": []
}}`})
	defer ts.Close()

	cs := NewClient(ts.URL, "KEY", "SECRET")
	ssh := &SSHKeyPair{
		Name: "foo",
	}
	if err := cs.Get(ssh); err == nil {
		t.Errorf("An error was expected")
	}
}

func TestDelSSHKeyPair(t *testing.T) {
	ts := newServer(response{200, `
{"deletesshkeypair": {
	"success": "true"
}}`})
	defer ts.Close()

	cs := NewClient(ts.URL, "KEY", "SECRET")
	ssh := &SSHKeyPair{
		Name: "test",
	}
	if err := cs.Delete(ssh); err != nil {
		t.Error(err)
	}
}
