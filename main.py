import os
import re
import subprocess
import sys
import traceback

VALIDATE_POLICY = "VALIDATE_POLICY"
CHECK_NO_NEW_ACCESS = "CHECK_NO_NEW_ACCESS"
CHECK_ACCESS_NOT_GRANTED = "CHECK_ACCESS_NOT_GRANTED"

CLI_POLICY_VALIDATOR = "tf-policy-validator"

TREAT_FINDINGS_AS_NON_BLOCKING = "INPUT_TREAT-FINDINGS-AS-NON-BLOCKING"

POLICY_CHECK_TYPE = "INPUT_POLICY-CHECK-TYPE"

# excluding the "INPUT_POLICY-CHECK-TYPE". Contains only other required inputs in tf-policy-validator
COMMON_REQUIRED_INPUTS = {"INPUT_TEMPLATE-PATH", "INPUT_REGION"}

VALIDATE_POLICY_SPECIFIC_REQUIRED_INPUTS = set()

CHECK_NO_NEW_ACCESS_SPECIFIC_REQUIRED_INPUTS = {
    "INPUT_TEMPLATE-PATH",
    "INPUT_REGION",
    "INPUT_REFERENCE-POLICY",
    "INPUT_REFERENCE-POLICY-TYPE",
}

CHECK_ACCESS_NOT_GRANTED_SPECIFIC_REQUIRED_INPUTS = {"INPUT_ACTIONS"}

# excluding the "INPUT_POLICY-CHECK-TYPE". Contains only other required inputs in cfn-policy-validator
COMMON_OPTIONAL_INPUTS = {
    "INPUT_IGNORE-FINDING",
    "INPUT_ALLOW-DYNAMIC-REF-WITHOUT-VERSION",
    "INPUT_EXCLUDE-RESOURCE-TYPES",
}

VALIDATE_POLICY_SPECIFIC_OPTIONAL_INPUTS = {
    "INPUT_ALLOW-EXTERNAL-PRINCIPALS",
    "INPUT_TREAT-FINDING-TYPE-AS-BLOCKING",
}

# Excluding the TREAT-FINDINGS-AS-NON-BLOCKING which is a flag and needs special handling
CHECK_NO_NEW_ACCESS_SPECIFIC_OPTIONAL_INPUTS = set()

# Excluding the TREAT-FINDINGS-AS-NON-BLOCKING which is a flag and needs special handling
CHECK_ACCESS_NOT_GRANTED_SPECIFIC_OPTIONAL_INPUTS = set()


VALID_POLICY_CHECK_TYPES = [
    VALIDATE_POLICY,
    CHECK_NO_NEW_ACCESS,
    CHECK_ACCESS_NOT_GRANTED,
]

# Name of the output defined in the GitHub action schema
ACTION_OUTPUT_RESULT = "result"


def main():
    policy_check = get_policy_check_type()
    required_inputs = get_required_inputs(policy_check)
    optional_inputs = get_optional_inputs(policy_check)
    command_lst = build_command(
        policy_check, required_inputs=required_inputs, optional_inputs=optional_inputs
    )
    command_lst.extend(
        ["--config", get_config()]
    )  # Config is required for handling terraform templates
    result = execute_command(command_lst)
    set_output(result)
    return


# Get the policy check name
def get_policy_check_type():
    policy_check = os.environ[POLICY_CHECK_TYPE]
    if policy_check not in VALID_POLICY_CHECK_TYPES:
        raise ValueError(
            "Invalid value of policy-check-type: {}. Valid values are: {}".format(
                policy_check, VALID_POLICY_CHECK_TYPES
            )
        )
    return policy_check


def get_flag_name(val):
    return val.removeprefix("INPUT_").lower()


def get_required_inputs(policy_check):
    required_inputs = {}
    check_specific_required_inputs = None
    if policy_check == VALIDATE_POLICY:
        check_specific_required_inputs = VALIDATE_POLICY_SPECIFIC_REQUIRED_INPUTS
    elif policy_check == CHECK_NO_NEW_ACCESS:
        check_specific_required_inputs = CHECK_NO_NEW_ACCESS_SPECIFIC_REQUIRED_INPUTS
    elif policy_check == CHECK_ACCESS_NOT_GRANTED:
        check_specific_required_inputs = (
            CHECK_ACCESS_NOT_GRANTED_SPECIFIC_REQUIRED_INPUTS
        )
    required_inputs = COMMON_REQUIRED_INPUTS.union(check_specific_required_inputs)
    return required_inputs


def get_optional_inputs(policy_check):
    optional_inputs = {}
    check_specific_optional_inputs = None
    if policy_check == VALIDATE_POLICY:
        check_specific_optional_inputs = VALIDATE_POLICY_SPECIFIC_OPTIONAL_INPUTS
    elif policy_check == CHECK_NO_NEW_ACCESS:
        check_specific_optional_inputs = CHECK_NO_NEW_ACCESS_SPECIFIC_OPTIONAL_INPUTS
    elif policy_check == CHECK_ACCESS_NOT_GRANTED:
        check_specific_optional_inputs = (
            CHECK_ACCESS_NOT_GRANTED_SPECIFIC_OPTIONAL_INPUTS
        )
    optional_inputs = check_specific_optional_inputs.union(COMMON_OPTIONAL_INPUTS)
    return optional_inputs


def build_command(policy_check_type, required_inputs, optional_inputs):
    cli_tool_name = CLI_POLICY_VALIDATOR
    command_lst = []
    cli_operation_name = (
        "validate"
        if policy_check_type == VALIDATE_POLICY
        else policy_check_type.replace("_", "-").lower()
    )

    sub_command_required_lst = get_sub_command(required_inputs, True)
    sub_command_optional_lst = get_sub_command(optional_inputs, False)

    command_lst.append(cli_tool_name)
    command_lst.append(cli_operation_name)
    command_lst.extend(sub_command_required_lst)
    command_lst.extend(sub_command_optional_lst)

    treat_findings_as_non_blocking_flag = get_treat_findings_as_non_blocking_flag(
        policy_check_type
    )
    if len(treat_findings_as_non_blocking_flag) > 0:
        command_lst.extend(get_treat_findings_as_non_blocking_flag(policy_check_type))
    return command_lst


def get_sub_command(inputFields, areRequiredFields):
    flags = []

    for input in inputFields:
        # The default values to these environment variable when passed to docker is empty string through GitHub Actions
        if os.environ[input] != "":
            flag_name = get_flag_name(input)
            flags.extend(["--{}".format(flag_name), os.environ[input]])
        elif areRequiredFields:
            raise ValueError("Missing value for required field: {}", input)

    return flags


def get_treat_findings_as_non_blocking_flag(policy_check):
    # This is specific to custom checks - CheckAccessNotGranted & CheckNoNewAccess
    if policy_check in (CHECK_ACCESS_NOT_GRANTED, CHECK_NO_NEW_ACCESS):
        val = os.environ[TREAT_FINDINGS_AS_NON_BLOCKING]
        if val == "True":
            return ["--{}".format(get_flag_name(TREAT_FINDINGS_AS_NON_BLOCKING))]
        elif val == "False":
            return ""
        else:
            raise ValueError(
                "Invalid value for {}: {}".format(TREAT_FINDINGS_AS_NON_BLOCKING, val)
            )
    return ""


def get_config():
    return os.environ["TERRAFORM_CONFIG_DEFAULT"]


def execute_command(command):
    try:
        result = subprocess.run(
            command, check=True, stdout=subprocess.PIPE, encoding="utf-8"
        ).stdout
        return result
    except subprocess.CalledProcessError as err:
        print(
            "error code: {}, traceback: {}, output: {}".format(
                err.returncode, err.with_traceback, err.output
            )
        )
        if err.returncode == 2:
            set_output(err.output)
        raise
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise


def set_output(val):
    formatted_result = format_result(val)
    set_github_action_output(ACTION_OUTPUT_RESULT, formatted_result)
    return


def format_result(result):
    result = re.sub(r"[\n\t\s]*", "", result)
    print("result={}".format(result))
    return result


#  Output value should be set by writing to the outputs in the environment file
#  https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-output-parameter
def set_github_action_output(output_name, output_value):
    with open(os.path.abspath(os.environ["GITHUB_OUTPUT"]), "a") as f:
        f.write(f"{output_name}={output_value}")
    return


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc()
        print(f"ERROR: Unexpected error occurred. {str(e)}", file=sys.stderr)
        exit(1)
