package node

import "testing"

func TestUploadConfigurationRequiresExplicitConsentAndCorrectSlots(t *testing.T) {
	request := SpeedTestRequest{URL: "https://upload.example/test", Direction: "upload"}
	if request.Validate() == nil {
		t.Fatal("implicit upload consent")
	}
	request.AllowUpload = true
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	config := MonitoringConfig{Speed: SpeedSchedule{Test: request}}
	if config.Validate() == nil {
		t.Fatal("POST in legacy download schedule")
	}
	request.Direction = ""
	upload := SpeedSchedule{Enabled: true, Test: request}
	config = MonitoringConfig{UploadSpeed: &upload}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	effective := config.Effective()
	if effective.Speed.Enabled || effective.UploadSpeed.Test.Direction != "upload" || upload.Test.Direction != "" {
		t.Fatal("mutated source or enabled download")
	}
	upload.Test.AllowUpload = false
	if config.Validate() == nil {
		t.Fatal("automatic upload without consent")
	}
	upload.Test.AllowUpload = true
	policy := SelectorPolicy{UploadTest: &request, UploadTarget: request.URL}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	request.AllowUpload = false
	if policy.Validate() == nil {
		t.Fatal("selector upload without consent")
	}
}
