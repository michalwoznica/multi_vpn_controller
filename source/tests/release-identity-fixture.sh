# Shared current-release expectations for public regressions.
# Source only after ROOT has been set to the repository root.
[[ -n ${ROOT:-} && -d $ROOT/source ]] || { printf '%s\n' 'release identity fixture requires ROOT' >&2; return 1; }
MVC_TEST_RELEASE_VERSION_FILE=$ROOT/source/release-version
[[ -f $MVC_TEST_RELEASE_VERSION_FILE && ! -L $MVC_TEST_RELEASE_VERSION_FILE ]] || { printf '%s\n' 'release-version missing or unsafe' >&2; return 1; }
mapfile -t MVC_TEST_RELEASE_VERSION_LINES < "$MVC_TEST_RELEASE_VERSION_FILE" || return 1
(( ${#MVC_TEST_RELEASE_VERSION_LINES[@]} == 1 )) || { printf '%s\n' 'release-version must contain exactly one line' >&2; return 1; }
MVC_TEST_RELEASE_VERSION=${MVC_TEST_RELEASE_VERSION_LINES[0]}
[[ $MVC_TEST_RELEASE_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf '%s\n' 'release-version is invalid' >&2; return 1; }
MVC_TEST_RELEASE_ID=${MVC_TEST_RELEASE_VERSION//./}
MVC_TEST_RELEASE_BANNER="Multi VPN Controller $MVC_TEST_RELEASE_VERSION"
MVC_TEST_RELEASE_CHECKPOINT="MVC_V${MVC_TEST_RELEASE_ID}_RELEASE"
MVC_TEST_RELEASE_AUTHORITY="audited-dispatch-mvc-v${MVC_TEST_RELEASE_ID}-release"
readonly MVC_TEST_RELEASE_VERSION MVC_TEST_RELEASE_ID MVC_TEST_RELEASE_BANNER MVC_TEST_RELEASE_CHECKPOINT MVC_TEST_RELEASE_AUTHORITY
unset MVC_TEST_RELEASE_VERSION_LINES MVC_TEST_RELEASE_VERSION_FILE
