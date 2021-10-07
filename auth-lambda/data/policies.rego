package opablog

default allow = false

allow {
	input.Usergroup == data.GroupPermissions[input.Resource][_]
}
