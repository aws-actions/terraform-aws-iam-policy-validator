import os
import subprocess
import unittest
from main import get_policy_check_type, get_required_inputs, get_optional_inputs, get_sub_command
from main import get_treat_findings_as_non_blocking_flag, build_command, execute_command, set_output

CLI_POLICY_VALIDATOR = "tf-policy-validator"

POLICY_CHECK_TYPE = "INPUT_POLICY-CHECK-TYPE"

NOT_VALIDATE_POLICY = "NOT_VALIDATE_POLICY"
VALIDATE_POLICY = "VALIDATE_POLICY"
CHECK_NO_NEW_ACCESS = "CHECK_NO_NEW_ACCESS"
CHECK_ACCESS_NOT_GRANTED = "CHECK_ACCESS_NOT_GRANTED"

COMMON_REQUIRED_INPUTS = {"INPUT_TEMPLATE-PATH", "INPUT_REGION"}

TREAT_FINDINGS_AS_NON_BLOCKING = "INPUT_TREAT-FINDINGS-AS-NON-BLOCKING"

# assertRaises(SomeCoolException, mymod.myfunc)
class TfpvTest(unittest.TestCase):
    # test_get_type_case1: failure expected because required os.environ[] are not set")
    @unittest.expectedFailure
    def test_get_type_case1(self):
        assertRaises(ValueError, get_policy_check_type)

    # test_get_type_case2: failure expected because os.environ[] is set to an invalid value")
    @unittest.expectedFailure
    def test_get_type_case2(self):
        os.environ[POLICY_CHECK_TYPE] = NOT_VALIDATE_POLICY
        assertRaises(ValueError, get_policy_check_type)

    def test_get_type_case3(self):
        os.environ[POLICY_CHECK_TYPE] = VALIDATE_POLICY
        policy_type = get_policy_check_type()
        assert policy_type == VALIDATE_POLICY

    # test_get_required_input_case4: failure expected because an invalid policy_check_type is provided")
    @unittest.expectedFailure
    def test_get_required_input_case4(self):
        policy_check = "INVALIDATE_POLICY"
        result = get_required_inputs(policy_check)
        assert result == {"INPUT_TEMPLATE-PATH",  "INPUT_REGION"}

    def test_get_required_input_case5(self):
        policy_check = "VALIDATE_POLICY"
        result = get_required_inputs(policy_check)
        assert result == {"INPUT_TEMPLATE-PATH",  "INPUT_REGION"}

    def test_get_required_input_case6(self):
        policy_check = "CHECK_NO_NEW_ACCESS"
        result = get_required_inputs(policy_check)
        assert result == {"INPUT_TEMPLATE-PATH",  "INPUT_REGION", "INPUT_REFERENCE-POLICY",  "INPUT_REFERENCE-POLICY-TYPE"}

    def test_get_required_input_case7(self):
        policy_check = "CHECK_ACCESS_NOT_GRANTED"
        result = get_required_inputs(policy_check)
        assert result == {"INPUT_TEMPLATE-PATH",  "INPUT_REGION", "INPUT_ACTIONS"}


    # test_get_optional_input_case8: failure expected because an invalid policy_check_type is provided")
    @unittest.expectedFailure
    def test_get_optional_input_case8(self):
        policy_check = "INVALIDATE_POLICY"
        result = get_optional_inputs(policy_check)
        assert result == {"INPUT_IGNORE-FINDING",  "INPUT_ALLOW-DYNAMIC-REF-WITHOUT-VERSION",  "INPUT_EXCLUDE-RESOURCE-TYPES"}

    def test_get_optional_input_case9(self):
        policy_check = "VALIDATE_POLICY"
        result = get_optional_inputs(policy_check)
        assert result == {"INPUT_ALLOW-EXTERNAL-PRINCIPALS",  "INPUT_TREAT-FINDING-TYPE-AS-BLOCKING", "INPUT_IGNORE-FINDING", \
                          "INPUT_ALLOW-DYNAMIC-REF-WITHOUT-VERSION",  "INPUT_EXCLUDE-RESOURCE-TYPES"}

    def test_get_optional_input_case10(self):
        policy_check = "CHECK_NO_NEW_ACCESS"
        result = get_optional_inputs(policy_check)
        assert result == {"INPUT_IGNORE-FINDING",  "INPUT_ALLOW-DYNAMIC-REF-WITHOUT-VERSION",  "INPUT_EXCLUDE-RESOURCE-TYPES"}

    def test_get_optional_input_case11(self):
        policy_check = "CHECK_NO_NEW_ACCESS"
        policy_check = "CHECK_ACCESS_NOT_GRANTED"
        result = get_optional_inputs(policy_check)
        assert result == {"INPUT_IGNORE-FINDING",  "INPUT_ALLOW-DYNAMIC-REF-WITHOUT-VERSION",  "INPUT_EXCLUDE-RESOURCE-TYPES"}


    # test_get_sub_command_case1: failure expected because required os.environ[]s are not set
    @unittest.expectedFailure
    def test_get_sub_command_case12(self):
        required = {"INPUT_TEMPLATE-PATH",  "INPUT_REGION"}
        assertRaises(ValueError, get_sub_command, required, True)

    def test_get_sub_command_case13(self):
        tft = os.getcwd() + './tf_validate.json'
        os.environ['INPUT_TEMPLATE-PATH'] = tft
        os.environ['INPUT_REGION'] = 'us-west-2'
        required = {"INPUT_TEMPLATE-PATH",  "INPUT_REGION"}
        expected = ['--template-path', tft, '--region', 'us-west-2']
        flags = get_sub_command(required, True)
        assert set(flags) == set(expected)

    # test_get_treat_findings_as_non_blocking_flag_case1: failure expected because os.environ[TREAT_FINDINGS_AS_NON_BLOCKING] is not set
    @unittest.expectedFailure
    def test_get_treat_findings_as_non_blocking_flag_case14(self):
        policy_check = CHECK_NO_NEW_ACCESS
        assertRaises(ValueError, get_treat_findings_as_non_blocking_flag, policy_check)
        
    def test_get_treat_findings_as_non_blocking_flag_case15(self):
        policy_check = VALIDATE_POLICY
        result = get_treat_findings_as_non_blocking_flag(policy_check)
        assert result == "" 
        
    def test_get_treat_findings_as_non_blocking_flag_case16(self):
        policy_check = CHECK_ACCESS_NOT_GRANTED
        os.environ[TREAT_FINDINGS_AS_NON_BLOCKING] = 'True'
        result = get_treat_findings_as_non_blocking_flag(policy_check)
        assert result == ['--treat-findings-as-non-blocking']

    def test_get_treat_findings_as_non_blocking_flag_case17(self):
        policy_check = CHECK_ACCESS_NOT_GRANTED
        os.environ[TREAT_FINDINGS_AS_NON_BLOCKING] = 'False'
        result = get_treat_findings_as_non_blocking_flag(policy_check)
        assert result == "" 

    def test_build_command_case18(self):
        policy_check = VALIDATE_POLICY
        tft = os.getcwd() + './tf_validate.json'
        os.environ['INPUT_TEMPLATE-PATH'] = tft 
        os.environ['INPUT_REGION'] = 'us-west-2'
        os.environ['TREAT_FINDINGS_AS_NON_BLOCKING'] = 'False'
        os.environ['INPUT_IGNORE-FINDING'] = 'PASS_ROLE_WITH_STAR_IN_RESOURCE'
        required = {"INPUT_TEMPLATE-PATH",  "INPUT_REGION"}
        optional = {"INPUT_IGNORE-FINDING"}
        command = build_command(policy_check, required, optional)
        # print("command {}".format(command))
        expected = set([CLI_POLICY_VALIDATOR, 'validate', '--template-path', tft, '--region', 'us-west-2', '--ignore-finding', 'PASS_ROLE_WITH_STAR_IN_RESOURCE'])
        command_set = set(command)
        assert command_set == expected

#     def test_execute_command_case19(self):
#         tft = os.getcwd() + '/tf_validate.json'
#         cfg = os.getcwd() + '/default.yaml'
#         command = [CLI_POLICY_VALIDATOR, 'validate', '--config', cfg, '--template-path', tft, '--region', 'us-west-2', '--treat-finding-type-as-blocking', 'ERROR']
#         result = execute_command(command)
#         assert result.find("BlockingFindings") != -1

    def test_set_output_case20(self):
        os.environ['GITHUB_OUTPUT'] = '/tmp/f1'
        val = '{"BlockingFindings": [],"NonBlockingFindings": []}'
        set_output(val)
        res = subprocess.run(["grep", "BlockingFindings", "/tmp/f1"], check=True, capture_output=True, encoding="utf-8").stdout
        subprocess.run(["rm", "/tmp/f1"])
        assert res.find("BlockingFindings") != -1

