import os
import subprocess
import unittest
import pytest
from parameterized import parameterized
from main import get_policy_check_type, get_required_inputs, get_optional_inputs, get_sub_command
from main import get_treat_findings_as_non_blocking_flag, build_command, execute_command, set_output

from main import CLI_POLICY_VALIDATOR, POLICY_CHECK_TYPE, VALIDATE_POLICY, CHECK_NO_NEW_ACCESS, CHECK_ACCESS_NOT_GRANTED
from main import COMMON_REQUIRED_INPUTS, TREAT_FINDINGS_AS_NON_BLOCKING

from unittest.mock import patch

class TfpvTest(unittest.TestCase):
    # case 1: test_get_type_ENVIRON_NOT_SET: failure expected because required os.environ[] are not set
    @unittest.expectedFailure
    def test_get_type_ENVIRON_NOT_SET(self):
        assertRaises(ValueError, get_policy_check_type)

    # case 2: test_get_type_INVALID_POLICY_CHECK: failure expected because os.environ[] is set to an invalid value
    @unittest.expectedFailure
    def test_get_type_INVALID_POLICY_CHECK(self):
        os.environ[POLICY_CHECK_TYPE] = INVALID_POLICY_CHECK
        assertRaises(ValueError, get_policy_check_type)

    # case 3, 4, 5: test_get_type_WITH_VALIDATE_POLICY: success with valid POLICY_CHECK_TYPE
    @parameterized.expand([VALIDATE_POLICY, CHECK_NO_NEW_ACCESS, CHECK_ACCESS_NOT_GRANTED])
    def test_get_type_WITH_VALID_POLICY_CHECK(self, policy_check_type):
        os.environ[POLICY_CHECK_TYPE] = policy_check_type
        policy_type = get_policy_check_type()
        self.assertEqual(policy_type, policy_check_type)

    # case 6: test_get_required_input_INVALID_POLICY_CHECK: failure expected because an invalid policy_check_type is provided
    @unittest.expectedFailure
    def test_get_required_input_INVALID_POLICY_CHECK(self):
        policy_check = "INVALID_POLICY_CHECK"
        assert get_required_inputs(policy_check) is None

    # case 7, 8, 9: test_get_required_input_WITH_VALIDATE_POLICY: success as a valid POLICY_CHECK_TYPE is provided: VALIDATE_POLICY
    @parameterized.expand([VALIDATE_POLICY, CHECK_NO_NEW_ACCESS, CHECK_ACCESS_NOT_GRANTED])
    def test_get_required_input_WITH_VALID_POLICY_CHECK(self, policy_check_type):
        result = get_required_inputs(policy_check_type)
        if policy_check_type == VALIDATE_POLICY:
            self.assertEqual(result, {"INPUT_TEMPLATE-PATH",  "INPUT_REGION"})
        elif policy_check_type == CHECK_NO_NEW_ACCESS:
            self.assertEqual(result, {"INPUT_TEMPLATE-PATH",  "INPUT_REGION", "INPUT_REFERENCE-POLICY",  "INPUT_REFERENCE-POLICY-TYPE"})
        else:
            self.assertEqual(result, {"INPUT_TEMPLATE-PATH",  "INPUT_REGION", "INPUT_ACTIONS"})

    # case 10: test_get_optional_input_INVALID_POLICY_CHECK: failure expected because an invalid policy_check_type is provided
    @unittest.expectedFailure
    def test_get_optional_input_INVALID_POLICY_CHECK(self):
        policy_check = INVALID_POLICY_CHECK
        result = get_optional_inputs(policy_check)
        assertEqual(result, {"INPUT_IGNORE-FINDING",  "INPUT_ALLOW-DYNAMIC-REF-WITHOUT-VERSION",  "INPUT_EXCLUDE-RESOURCE-TYPES"})

    # case 11, 12, 13: test_get_optional_input_WITH_VALID_POLICY_CHECK: success as a valid POLICY_CHECK_TYPE is provided
    @parameterized.expand([VALIDATE_POLICY, CHECK_NO_NEW_ACCESS, CHECK_ACCESS_NOT_GRANTED])
    def test_get_optional_input_WITH_VALID_POLICY_CHECK(self, policy_check_type):
        result = get_optional_inputs(policy_check_type)
        if policy_check_type == VALIDATE_POLICY:
            self.assertEqual(result, {"INPUT_ALLOW-EXTERNAL-PRINCIPALS",  "INPUT_TREAT-FINDING-TYPE-AS-BLOCKING", "INPUT_IGNORE-FINDING",
                          "INPUT_ALLOW-DYNAMIC-REF-WITHOUT-VERSION",  "INPUT_EXCLUDE-RESOURCE-TYPES"})
        elif policy_check_type == CHECK_NO_NEW_ACCESS:
            self.assertEqual(result, {"INPUT_IGNORE-FINDING",  "INPUT_ALLOW-DYNAMIC-REF-WITHOUT-VERSION",  "INPUT_EXCLUDE-RESOURCE-TYPES"})
        else:
            self.assertEqual(result, {"INPUT_IGNORE-FINDING",  "INPUT_ALLOW-DYNAMIC-REF-WITHOUT-VERSION",  "INPUT_EXCLUDE-RESOURCE-TYPES"})

    # case 14: test_get_sub_command_ENVIRON_NOT_SET: failure expected because required os.environ[]s are not set
    @unittest.expectedFailure
    def test_get_sub_command_ENVIRON_NOT_SET(self):
        required = {"INPUT_TEMPLATE-PATH",  "INPUT_REGION"}
        assertRaises(ValueError, get_sub_command, required, True)

    # case 15: test_get_sub_command_MEET_REQUIRED_INPUTS: success as valid inputs are provided.
    def test_get_sub_command_MEET_REQUIRED_INPUTS(self):
        tft = os.getcwd() + './main.py'
        os.environ['INPUT_TEMPLATE-PATH'] = tft
        os.environ['INPUT_REGION'] = 'us-west-2'
        required = {"INPUT_TEMPLATE-PATH",  "INPUT_REGION"}
        expected = ['--template-path', tft, '--region', 'us-west-2']
        flags = get_sub_command(required, True)
        self.assertEqual(set(flags), set(expected))

    # case 16: test_get_treat_findings_as_non_blocking_flag_ENVIRON_NOT_SET: failure expected because os.environ[TREAT_FINDINGS_AS_NON_BLOCKING] is not set
    @unittest.expectedFailure
    def test_get_treat_findings_as_non_blocking_flag_ENVIRON_NOT_SET(self):
        policy_check = CHECK_NO_NEW_ACCESS
        assertRaises(ValueError, get_treat_findings_as_non_blocking_flag, policy_check)
        
    # case 17: test_get_treat_findings_as_non_blocking_flag_VALIDATE_POLICY: pass
    def test_get_treat_findings_as_non_blocking_flag_VALIDATE_POLICY(self):
        policy_check = VALIDATE_POLICY
        result = get_treat_findings_as_non_blocking_flag(policy_check)
        self.assertEqual(result, "")
        
    # case 18: test_get_treat_findings_as_non_blocking_flag_CHECK_ACCESS_NOT_GRANTED_True: pass, a string of flag returned
    def test_get_treat_findings_as_non_blocking_flag_CHECK_ACCESS_NOT_GRANTED_True(self):
        policy_check = CHECK_ACCESS_NOT_GRANTED
        os.environ[TREAT_FINDINGS_AS_NON_BLOCKING] = 'True'
        result = get_treat_findings_as_non_blocking_flag(policy_check)
        self.assertEqual(result, ['--treat-findings-as-non-blocking'])

    # case 19: test_get_treat_findings_as_non_blocking_flag_CHECK_ACCESS_NOT_GRANTED_False: pass, an empty string returned
    def test_get_treat_findings_as_non_blocking_flag_CHECK_ACCESS_NOT_GRANTED_False(self):
        policy_check = CHECK_ACCESS_NOT_GRANTED
        os.environ[TREAT_FINDINGS_AS_NON_BLOCKING] = 'False'
        result = get_treat_findings_as_non_blocking_flag(policy_check)
        self.assertEqual(result, "")

    # case 20: test_build_command_VALIDATE_POLICY: pass with correct parameters.
    def test_build_command_VALIDATE_POLICY(self):
        policy_check = VALIDATE_POLICY
        tft = os.getcwd() + './main.py'
        os.environ['INPUT_TEMPLATE-PATH'] = tft 
        os.environ['INPUT_REGION'] = 'us-west-2'
        os.environ['TREAT_FINDINGS_AS_NON_BLOCKING'] = 'False'
        os.environ['INPUT_IGNORE-FINDING'] = 'PASS_ROLE_WITH_STAR_IN_RESOURCE'
        required = {"INPUT_TEMPLATE-PATH",  "INPUT_REGION"}
        optional = {"INPUT_IGNORE-FINDING"}
        command = build_command(policy_check, required, optional)
        expected = set([CLI_POLICY_VALIDATOR, 'validate', '--template-path', tft, '--region', 'us-west-2', '--ignore-finding', 'PASS_ROLE_WITH_STAR_IN_RESOURCE'])
        command_set = set(command)
        self.assertEqual(command_set, expected)

    # case 21: test_execute_command_EXCEPTION: exception raised
    @patch("subprocess.run", side_effect=Exception("invalid-input"))
    def test_execute_command_EXCEPTION(self, mock_run):
        with pytest.raises(Exception) as exc:
            result = execute_command()
            assertNotEqual(str(exc.value).find("invalid-input"), -1)

    # case 21: test_execute_command_VALIDATE: pass with mockrun
    @patch("main.subprocess.run")
    def test_execute_command_VALIDATE(self, mock_run):
        command = [CLI_POLICY_VALIDATOR, 'validate']
        expected = "pass"

        completed_process = subprocess.CompletedProcess(args=['command', 'args'], returncode=0, stdout=expected, stderr=b'error')
        mock_run.return_value = completed_process

        result = execute_command(command)
        self.assertEqual(result, expected)

    # case 23: test_set_output: pass
    def test_set_output_WRITE_TO_FILE(self):
        os.environ['GITHUB_OUTPUT'] = '/tmp/f1'
        val = '{"BlockingFindings": [],"NonBlockingFindings": []}'
        set_output(val)
        res = subprocess.run(["grep", "BlockingFindings", "/tmp/f1"], check=True, capture_output=True, encoding="utf-8").stdout
        subprocess.run(["rm", "/tmp/f1"])
        self.assertNotEqual(res.find("BlockingFindings"), -1)

