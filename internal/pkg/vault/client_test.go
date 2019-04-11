/*******************************************************************************
 * Copyright 2019 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package vault

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

/** TODO uncomment when development resumes

func TestClient_GetValue(t *testing.T) {
	client := Client{}

	value, err := client.GetValue("test")

	if value == "" {
		t.Error("Unexpected value returned")
	}

	if err != nil {
		t.Error(err)
	}
}

func TestClient_SetValue(t *testing.T) {
	client := Client{}

	err := client.SetValue("test")

	if err != nil {
		t.Error(err)
	}
}

func TestClient_DeleteValue(t *testing.T) {
	client := Client{}

	err := client.DeleteValue("test")

	if err != nil {
		t.Error(err)
	}
}

*/
