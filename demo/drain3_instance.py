from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

CONFIG_PATH = 'drain3.ini'

config = TemplateMinerConfig()
config.load(CONFIG_PATH)
drain3_instance = TemplateMiner(config=config)
