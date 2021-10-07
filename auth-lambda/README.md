A custom OPA Lambda authorizer to control access to our API. This is a request parameter-based OPA Lambda authorizer that receives the caller’s identity in a combination of headers and converts them as structured context data for OPA to make a policy decision and authorize our API call.

OPA Lambda authorizer evaluates the policy with the context data and will return an IAM policy object.

Data folder contains OPA policy data