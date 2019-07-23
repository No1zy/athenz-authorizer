/*
Copyright (C)  2018 Yahoo Japan Corporation Athenz team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package policy

import (
	"context"
	"math"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/kpango/gache"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
)

func TestTest_policyd_CheckPolicy(t *testing.T) {
	type fields struct {
		expireMargin     time.Duration
		rolePolicies     gache.Gache
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		pkp              pubkey.Provider
		etagCache        gache.Gache
		etagFlushDur     time.Duration
		etagExpTime      time.Duration
		athenzURL        string
		athenzDomains    []string
		client           *http.Client
	}
	type args struct {
		ctx      context.Context
		domain   string
		roles    []string
		action   string
		resource string
	}
	type test struct {
		name   string
		fields fields
		args   args
		want   error
	}
	tests := []test{
		{
			name: "check policy: control test",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					g.Set("domain:role.role1", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("action", "domain:resource", "deny")
							return a
						}(),
					})
					return g
				}(),
			},
			args: args{
				ctx:      context.Background(),
				domain:   "domain",
				roles:    []string{"role1", "role2", "role3", "role4"},
				action:   "action",
				resource: "resource",
			},
			want: errors.New("policy deny: Access Check was explicitly denied"),
		},
		{
			name: "check policy multiple deny deadlock",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					g.Set("domain:role.role1", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("action", "domain:resource", "deny")
							return a
						}(),
					})
					g.Set("domain:role.role2", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("action", "domain:resource", "deny")
							return a
						}(),
					})
					g.Set("domain:role.role3", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("action", "domain:resource", "deny")
							return a
						}(),
					})
					g.Set("domain:role.role4", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("action", "domain:resource", "deny")
							return a
						}(),
					})
					return g
				}(),
			},
			args: args{
				ctx:      context.Background(),
				domain:   "domain",
				roles:    []string{"role1", "role2", "role3", "role4"},
				action:   "action",
				resource: "resource",
			},
			want: errors.New("policy deny: Access Check was explicitly denied"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &policyd{
				expireMargin:     tt.fields.expireMargin,
				rolePolicies:     tt.fields.rolePolicies,
				refreshDuration:  tt.fields.refreshDuration,
				errRetryInterval: tt.fields.errRetryInterval,
				pkp:              tt.fields.pkp,
				etagCache:        tt.fields.etagCache,
				etagFlushDur:     tt.fields.etagFlushDur,
				etagExpTime:      tt.fields.etagExpTime,
				athenzURL:        tt.fields.athenzURL,
				athenzDomains:    tt.fields.athenzDomains,
				client:           tt.fields.client,
			}

			b := make([]byte, 10240)
			lenStart := runtime.Stack(b, true)
			// t.Log(string(b[:len]))
			err := p.CheckPolicy(tt.args.ctx, tt.args.domain, tt.args.roles, tt.args.action, tt.args.resource)
			if err == nil {
				if tt.want != nil {
					t.Errorf("CheckPolicy error: err: nil, want: %v", tt.want)
				}
			} else {
				if tt.want == nil {
					t.Errorf("CheckPolicy error: err: %v, want: nil", err)
				} else if err.Error() != tt.want.Error() {
					t.Errorf("CheckPolicy error: err: %v, want: %v", err, tt.want)
				}
			}

			// check runtime stack for go routine leak
			time.Sleep(time.Second) // wait for some background process to cleanup
			lenEnd := runtime.Stack(b, true)
			// t.Log(string(b[:len]))
			if math.Abs(float64(lenStart-lenEnd)) > 5 {
				t.Errorf("go routine leak:\n%v", string(b[:lenEnd]))
			}
		})
	}
}
