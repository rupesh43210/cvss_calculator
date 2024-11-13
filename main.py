import logging
from pathlib import Path
from excel_processor import ExcelProcessor
from vector_generator import VectorGenerator
from cvss_calculator import CVSSCalculator
from gui_interface import CVSSCalculatorGUI

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cvss_calculator.log'),
        logging.StreamHandler()
    ]
)

def main():
    try:
        # Initialize GUI
        gui = CVSSCalculatorGUI()
        
        # Start GUI main loop
        gui.run()
        
    except Exception as e:
        logging.error(f"Application error: {str(e)}")

if __name__ == "__main__":
    main()