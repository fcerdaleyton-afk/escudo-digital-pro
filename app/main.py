def setup_logging():
    """Setup comprehensive logging"""

    log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()

    # Create local logs directory
    os.makedirs('logs', exist_ok=True)

    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/mary_v5.log'),
            logging.FileHandler('logs/mary_v5_error.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

    logging.getLogger('uvicorn').setLevel(logging.INFO)
    logging.getLogger('fastapi').setLevel(logging.INFO)
    logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
    logging.getLogger('redis').setLevel(logging.WARNING)