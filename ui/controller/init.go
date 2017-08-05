package controller

import (
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/session"
)

var (
	globalSessions *session.Manager
)

func init() {
	globalSessions, _ = session.NewManager("memory", `{"cookieName":"gosessionid", "enableSetCookie,omitempty": true, "gclifetime":3600, "maxLifetime": 3600, "secure": false, "sessionIDHashFunc": "sha1", "sessionIDHashKey": "", "cookieLifeTime": 3600, "providerConfig": ""}`)
	go globalSessions.GC()

	beego.DelStaticPath("/static")
	beego.SetStaticPath("/", "static")

	// route mapping
	beego.Router("/api/v1", &IndexController{})

}
