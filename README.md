# Veracode Pipeline Script Template

Uses the Veracode APIs to create a starting point for a Pipeline Scan command line that is tailored to an application as already scanned in the Veracode Platform. Requires Python 3.

The script looks at the modules uploaded for the last successful scan of the application to determine if the application is a good candidate for Pipeline Scan, based on the compiler and architecture of each module. It also checks the analysis size as a proxy for the size of the application to make sure the application is not over 100MB.

The template command line will include the filename as well as Severity or CWE rules if those are present for static analysis in the policy attached to the applications.

## Setup

Clone this repository:

    git clone https://github.com/tjarrettveracode/veracode-pipeline-script-template

Install dependencies:

    cd veracode-pipeline-script-template
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python vcpipelinescript.py (arguments)

Otherwise you will need to set environment variables before running `vcarcher.py`:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python vcpipelinescript.py (arguments)

Arguments supported include:

* **`--application-id`, `-a`** : Application ID for the application for which you want a Pipeline Script template.

## Output

The script outputs a text file, **pipeline_template.txt**, based on the latest static scan completed for the application and the policy rules for the policy assigned to the application.

## Notes

1. The script requires a user with the Upload API or Submitter roles as described in the [Veracode Help Center](https://help.veracode.com/reader/TNIuE0856bMwmOQldtxbmQ/VCmovHKq7wSDn5AAjxt3nw)
2. If the application has never had a static scan performed, or the latest results are in an application language not reported by Pipeline Scan, the script returns an error.
