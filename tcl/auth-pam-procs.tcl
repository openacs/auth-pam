ad_library {
    Installation procs for authentication, account management, and password management,

    @author Lars Pind (lars@collaobraid.biz)
    @creation-date 2003-05-13
    @cvs-id $Id$
}

namespace eval auth {}
namespace eval auth::pam {}
namespace eval auth::pam::authentication {}
namespace eval auth::pam::password {}


ad_proc -private auth::pam::after_install {} {} {
    set spec {
        contract_name "auth_authentication"
        owner "auth-pam"
        name "PAM"
        pretty_name "PAM"
        aliases {
            Authenticate auth::pam::authentication::Authenticate
            GetParameters auth::pam::authentication::GetParameters
	    MergeUser auth::pam::authentication::MergeUser
        }
    }

    set auth_impl_id [acs_sc::impl::new_from_spec -spec $spec]

    set spec {
        contract_name "auth_password"
        owner "pam-auth"
        name "PAM"
        pretty_name "PAM"
        aliases {
            CanChangePassword auth::pam::password::CanChangePassword
            ChangePassword auth::pam::password::ChangePassword
            CanRetrievePassword auth::pam::password::CanRetrievePassword
            RetrievePassword auth::pam::password::RetrievePassword
            CanResetPassword auth::pam::password::CanResetPassword
            ResetPassword auth::pam::password::ResetPassword
            GetParameters auth::pam::password::GetParameters
        }
    }

    set pwd_impl_id [acs_sc::impl::new_from_spec -spec $spec]
}

ad_proc -private auth::pam::before_uninstall {} {} {

    acs_sc::impl::delete -contract_name "auth_authentication" -impl_name "PAM"

    acs_sc::impl::delete -contract_name "auth_password" -impl_name "PAM"

}


#####
#
# PAM Authentication Driver
#
#####


ad_proc -private auth::pam::authentication::Authenticate {
    username
    password
    {parameters {}}
    {authority_id {}}
} {
    Implements the Authenticate operation of the auth_authentication 
    service contract for PAM.
} {
    if { [ns_pam auth $username $password] } {
        set result(auth_status) ok
    } else {
        set result(auth_status) auth_error
    }

    set result(account_status) ok
    
    return [array get result]
}

ad_proc -private auth::pam::authentication::GetParameters {} {
    Implements the GetParameters operation of the auth_authentication 
    service contract for PAM.
} {
    return [list]
}


#####
#
# Password Driver
#
#####

ad_proc -private auth::pam::password::CanChangePassword {
    {parameters ""}
} {
    Implements the CanChangePassword operation of the auth_password 
    service contract for PAM.
} {
    return 1
}

ad_proc -private auth::pam::password::CanRetrievePassword {
    {parameters ""}
} {
    Implements the CanRetrievePassword operation of the auth_password 
    service contract for PAM.
} {
    return 0
}

ad_proc -private auth::pam::password::CanResetPassword {
    {parameters ""}
} {
    Implements the CanResetPassword operation of the auth_password 
    service contract for PAM.
} {
    return 0
}

ad_proc -private auth::pam::password::ChangePassword {
    username
    new_password
    {old_password ""}
    {parameters {}}
    {authority_id {}}
} {
    Implements the ChangePassword operation of the auth_password 
    service contract for PAM.
} {

    if ![empty_string_p $old_password] {
	if { [ns_pam chpass $username $old_password $new_passwd] } {
	    set result(password_status) ok
	} else {
	    set result(password_status) auth_error
	}
    } else {
	# TODO:
	# 'ns_pam chpass' requires the old password, so we need to
	# set the old_password as optional parameter in ns_pam chpass.
	#
	# ns_pam chpass username oldpassword newpasswd
	#
	# This is the change password command syntax. You supply the username old password and new password. you will be returned either:
	#
	# - 1 for a valid login
	# - 0 Indicating a bad username/password combo
	# It will return NS_ERROR and the string of the PAM error if there is an error. 

	if { [ns_pam chpass $username $old_password $new_passwd] } {
	    set result(password_status) ok
	} else {
	    ns_log error "auth-pam-procs.tcl: old password error"
	    set result(password_status) auth_error
	}
    }
    return [array get result]
}

ad_proc -private auth::pam::password::RetrievePassword {
    username
    parameters
} {
    Implements the RetrievePassword operation of the auth_password 
    service contract for PAM.
} {
}

ad_proc -private auth::pam::password::ResetPassword {
    username
    parameters
    {authority_id {}}
} {
    Implements the ResetPassword operation of the auth_password 
    service contract for PAM.
} {
}

ad_proc -private auth::pam::password::GetParameters {} {
    Implements the GetParameters operation of the auth_password
    service contract for PAM.
} {
    return [list]
}

ad_proc -private auth::pam::password::MergeUser {} {
    Implements the MergeUser operation of the auth_password
    service contract for PAM.
} {
}
