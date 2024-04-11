# Policy Validator for AWS IAM Policies in Terraform Templates

A GitHub Action that takes an Terraform template, parses the IAM policies attached to IAM roles, users, groups, and resources then runs them through IAM Access Analyzer [policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html) and (optionally) [custom policy checks](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-custom-policy-checks.html). Note that a charge is associated with each custom policy check. For more details about pricing, see [IAM Access Analyzer pricing](https://aws.amazon.com/iam/access-analyzer/pricing/).

## Inputs

See [action.yml](action.yaml) for the full documentation for this action's inputs and outputs.

<div data-section-="">
   <table title="Sheet4">
      <tbody>
         <tr>
            <td rowspan="2">Inputs</td>
            <td rowspan="2">Description</td>
            <td rowspan="2">Options</td>
            <td rowspan="2">Required</td>
            <td colspan="3">Applies To which policy-check-type</td>
         </tr>
         <tr>
            <td>VALIDATE_POLICY</td>
            <td>CHECK_NO_NEW_ACCESS</td>
            <td>CHECK_ACCESS_NOT_GRANTED</td>
         </tr>
         <tr>
            <td>policy-check-type</td>
            <td>Name of the policy check.<br />Note: Each value correponds to an IAM Access Analyzer API. <br />- <a href="https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html">ValidatePolicy</a><br />- <a href="https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckNoNewAccess.html">CheckNoNewAccess</a><br />- <a href="https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckAccessNotGranted.html">CheckAccessNotGranted</a></td>
            <td>VALIDATE_POLICY, CHECK_NO_NEW_ACCESS, CHECK_ACCESS_NOT_GRANTED.</td>
            <td>Yes</td>
            <td>✅</td>
            <td>✅</td>
            <td>✅</td>
         </tr>
         <tr>
            <td>template-path</td>
            <td>The path to the Terraform template.</td>
            <td>FILE_PATH.json</td>
            <td>Yes</td>
            <td>✅</td>
            <td>✅</td>
            <td>✅</td>
         </tr>
         <tr>
            <td>region</td>
            <td>The destination region the resources will be deployed to.</td>
            <td>REGION</td>
            <td>Yes</td>
            <td>✅</td>
            <td>✅</td>
            <td>✅</td>
         </tr>
         <tr>
            <td>ignore-finding</td>
            <td>Allow validation failures to be ignored. Specify as a comma separated list of findings to be ignored. Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name (e.g. "MyResource"), or a combination of both separated by a period.(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE"). Names of finding codes may change in IAM Access Analyzer over time.</td>
            <td>FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE</td>
            <td>No</td>
            <td>✅</td>
            <td>✅</td>
            <td>✅</td>
         </tr>
         <tr>
            <td>actions</td>
            <td>List of comma-separated actions. Example format - ACTION,ACTION,ACTION. <br /><br /><strong>This attribute is only considered and required when policy-check-type is "CHECK_ACCESS_NOT_GRANTED".</strong></td>
            <td>ACTION,ACTION,ACTION</td>
            <td>No</td>
            <td>❌</td>
            <td>❌</td>
            <td>✅</td>
         </tr>
         <tr>
            <td>reference-policy</td>
            <td>A JSON formatted file that specifies the path to the reference policy that is used for a permissions comparison. <br /><br /><strong>This attribute is only considered and required when policy-check-type is "CHECK_NO_NEW_ACCESS".</strong></td>
            <td>No</td>
            <td>❌</td>
            <td>✅</td>
            <td>❌</td>
         </tr>
         <tr>
            <td>reference-policy-type</td>
            <td>The policy type associated with the IAM policy under analysis and the reference policy. Valid values: IDENTITY, RESOURCE. <br /><br /><strong> This attribute is only considered and required when policy-check-type is "CHECK_NO_NEW_ACCESS"</strong></td>
            <td>No</td>
            <td>❌</td>
            <td>✅</td>
            <td>❌</td>
         </tr>
         <tr>
            <td>treat-finding-type-as-blocking</td>
            <td>Specify which finding types should be treated as blocking. Other finding types are treated as non blocking. If the tool detects any blocking finding types, it will exit with a non-zero exit code. If all findings are non blocking or there are no findings, the tool exits with an exit code of 0. Defaults to "ERROR" and "SECURITY_WARNING". Specify as a comma separated list of finding types that should be blocking. Pass "NONE" to ignore all findings. <br /><br /><strong>This attribute is only considered when policy-check-type is "VALIDATE_POLICY".</strong></td>
            <td>ERROR,SECURITY_WARNING,WARNING,SUGGESTION,NONE</td>
            <td>No</td>
            <td>✅</td>
            <td>❌</td>
            <td>❌</td>
         </tr>
         <tr>
            <td>treat-findings-as-non-blocking</td>
            <td>By default, the tool will exit with a non-zero exit code when it detects any findings. Set this flag to exit with an exit code of 0 when it detects findings. You can use this to run new checks in a shadow or log only mode before enforcing them. <br /><br /><strong>This attribute is considered only when policy-check-type is "CHECK_NO_NEW_ACCESS" or "CHECK_ACCESS_NOT_GRANTED".</strong></td>
            <td>No</td>
            <td>❌</td>
            <td>✅</td>
            <td>✅</td>
         </tr>
         <tr>
            <td>allow-external-principals</td>
            <td>A comma separated list of external principals that should be ignored. Specify as a comma separated list of a 12 digit AWS account ID, a federated web identity user, a federated SAML user, or an ARN. Specify "*" to allow anonymous access. (e.g. 123456789123,arn:aws:iam::111111111111:role/MyOtherRole,graph.facebook.com).</td>
            <td>ACCOUNT,ARN</td>
            <td>No</td>
            <td>✅</td>
            <td>❌</td>
            <td>❌</td>
         </tr>
         <tr>
            <td>allow-dynamic-ref-without-version</td>
            <td>Override the default behavior and allow dynamic SSM references without version numbers. The version number ensures that the SSM parameter value that was validated is the one that is deployed.</td>
            <td>No</td>
            <td>✅</td>
            <td>✅</td>
            <td>✅</td>
         </tr>
         <tr>
            <td>exclude-resource-types</td>
            <td>List of comma-separated resource types. Resource types should be the same as Cloudformation template resource names such as AWS::IAM::Role, AWS::S3::Bucket. Valid option syntax: AWS::SERVICE::RESOURCE.</td>
            <td>AWS::SERVICE::RESOURCE, AWS::SERVICE::RESOURCE</td>
            <td>No</td>
            <td>✅</td>
            <td>✅</td>
            <td>✅</td>
         </tr>
      </tbody>
   </table>
</div>

## Example Usage

**Before each of the following examples, make sure to include the following:**

- Setting up the role: Role used in the GitHub workflow should have necessary permissions required
  - to be called from the GitHub workflows, refer [this](https://aws.amazon.com/blogs/security/use-iam-roles-to-connect-github-actions-to-actions-in-aws/) for more details
  - to call the AWS APIs for the policy checks - ValidatePolicy, CheckNoNewAccess, CheckAccessNotGranted. Refer [this](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-checks-validating-policies.html) page for more details

```
    - name: Checkout Repo
        uses: actions/checkout@v4
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.POLICY_VALIDATOR_ROLE }} # Role with permissions to invoke access-analyzer:validate-policy,access-analyzer:check-no-new-access, access-analyzer:check-access-not-granted
          aws-region: aws-example-region
```

#### Using `VALIDATE_POLICY` CHECK

```
      - name: Run VALIDATE_POLICY Check
        id: run-validate-policy
        uses: aws-actions/terraform-aws-iam-policy-validator@v1
        with:
          policy-check-type: 'VALIDATE_POLICY'
          template-path: file-path-to-the-cfn-templates
          region: aws-example-region

```

#### Using for the `CHECK_NO_NEW_ACCESS` CHECK

```
      - name: Run CHECK_NO_NEW_ACCESS check
        id: run-check-no-new-access
        uses: aws-actions/terraform-aws-iam-policy-validator@v1
        with:
          policy-check-type: 'CHECK_NO_NEW_ACCESS'
          template-path: file-path-to-the-cfn-templates
          reference-policy: file-path-to-the-reference-policy
          reference-policy-type: policy-type-of-reference-policy
          region: aws-example-region
```

#### Using for the `CHECK_ACCESS_NOT_GRANTED` CHECK

```
      - name: Run CHECK_ACCESS_NOT_GRANTED check
        id: run-check-no-new-access
        uses: aws-actions/terraform-aws-iam-policy-validator@v1
        with:
          policy-check-type: 'CHECK_ACCESS_NOT_GRANTED'
          template-path: file-path-to-the-cfn-templates
          actions: "action1, action2.."
          region: aws-example-region
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
