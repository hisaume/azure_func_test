import logging
import os
import datetime
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import azure.functions as func

app = func.FunctionApp()

# Timer trigger — runs every day at midnight UTC
@app.timer_trigger(schedule="0 0 0 * * *", arg_name="myTimer", run_on_startup=False, use_monitor=True)
def kvsecretrotate(myTimer: func.TimerRequest) -> None:
    if myTimer.past_due:
        logging.warning('The timer is past due!')

    logging.info('Key Vault rotation function started.')

    try:
        # Environment variable defined in Function App settings
        key_vault_name = os.environ["KEYVAULT_NAME"]
        kv_uri = f"https://{key_vault_name}.vault.azure.net"

        # Authenticate via Managed Identity or Azure credentials
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=kv_uri, credential=credential)

        # Example: Rotate a secret called "DemoSecret"
        secret_name = "DemoSecret"
        new_secret_value = f"RotatedValue-{datetime.datetime.utcnow().isoformat()}"

        client.set_secret(secret_name, new_secret_value)
        logging.info(f"Secret '{secret_name}' rotated successfully in {key_vault_name}.")

    except Exception as e:
        logging.error(f"Secret rotation failed: {e}")

    logging.info('Key Vault rotation function executed.')
