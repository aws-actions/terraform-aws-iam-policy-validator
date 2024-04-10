# Use the official Python 3.10 image as the base image
FROM python:3.10
# or use office AWS images https://gallery.ecr.aws/docker/library/python

# Install tf-policy-validator
# Cloning the `terraform-iam-policy-validator` repo for default config for terraform templates
# ToDo: Once we start using the tags for releases, we should use the tag associated with the version we download by using flag --branch <tag>
RUN pip install tf-policy-validator==0.0.6 && git clone https://github.com/awslabs/terraform-iam-policy-validator.git

ENV TERRAFORM_CONFIG_DEFAULT=/terraform-iam-policy-validator/iam_check/config/default.yaml

COPY main.py /main.py

ENTRYPOINT ["python3", "/main.py"]