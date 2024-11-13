import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import logging
from excel_processor import ExcelProcessor
from vector_generator import VectorGenerator
from cvss_calculator import CVSSCalculator
import os

class CVSSCalculatorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CVSS Calculator")
        self.root.geometry("800x600")
        
        # Initialize processors
        self.vector_generator = VectorGenerator()
        self.cvss_calculator = CVSSCalculator()
        
        # Set initial directory to current working directory
        self.initial_dir = os.getcwd()
        
        self.setup_gui()

    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(
            main_frame, 
            text="CVSS Score Calculator", 
            font=('Arial', 14, 'bold')
        )
        title_label.pack(pady=10)

        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="5")
        file_frame.pack(fill=tk.X, padx=10, pady=5)

        # File path entry
        self.file_path_var = tk.StringVar()
        self.file_path_entry = ttk.Entry(
            file_frame,
            textvariable=self.file_path_var,
            width=60
        )
        self.file_path_entry.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill=tk.X)

        # Browse button
        self.select_button = ttk.Button(
            file_frame,
            text="Browse",
            command=self.browse_file
        )
        self.select_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Process button
        self.process_button = ttk.Button(
            file_frame,
            text="Process File",
            command=self.process_file,
            state='disabled'
        )
        self.process_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Progress frame
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="5")
        progress_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)

        # Status text with frame
        status_frame = ttk.Frame(progress_frame)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.status_text = tk.Text(status_frame, height=15, width=70)
        self.status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar for status text
        scrollbar = ttk.Scrollbar(status_frame, command=self.status_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.status_text.config(yscrollcommand=scrollbar.set)

        # Initial status message
        self.update_status("Please select an Excel file to begin...")

    def browse_file(self):
        """Handle file selection"""
        try:
            file_path = filedialog.askopenfilename(
                initialdir=self.initial_dir,
                title="Select Excel File",
                filetypes=[
                    ("Excel Files", "*.xlsx *.xls"),
                    ("All Files", "*.*")
                ]
            )
            
            if file_path:
                self.file_path_var.set(file_path)
                self.process_button.config(state='normal')
                self.initial_dir = os.path.dirname(file_path)
                self.update_status(f"Selected file: {file_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error selecting file: {str(e)}")
            logging.error(f"Error selecting file: {str(e)}")

    def process_file(self):
        """Process the selected file"""
        file_path = self.file_path_var.get()
        
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file first.")
            return
            
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "Selected file does not exist.")
            return
            
        try:
            self.update_status(f"Processing file: {file_path}")
            self.disable_inputs()
            
            # Process the file
            excel_processor = ExcelProcessor(file_path, self)
            result = excel_processor.process_file(
                self.vector_generator,
                self.cvss_calculator
            )
            
            if result:
                messagebox.showinfo(
                    "Success",
                    f"Processing complete!\nResults saved to: {result}"
                )
            else:
                messagebox.showerror(
                    "Error",
                    "Failed to process file. Check the status log for details."
                )
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            logging.error(f"Error processing file: {str(e)}")
            
        finally:
            self.enable_inputs()
            self.update_status("Ready for next file...")

    def disable_inputs(self):
        """Disable input controls during processing"""
        self.select_button.config(state='disabled')
        self.process_button.config(state='disabled')
        self.file_path_entry.config(state='disabled')

    def enable_inputs(self):
        """Enable input controls after processing"""
        self.select_button.config(state='normal')
        self.process_button.config(state='normal')
        self.file_path_entry.config(state='normal')

    def update_status(self, message):
        """Update status text with new message"""
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.see(tk.END)
        self.root.update()

    def update_progress(self, value):
        """Update progress bar"""
        self.progress_var.set(value)
        self.root.update()

    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('cvss_calculator.log'),
            logging.StreamHandler()
        ]
    )
    
    # Create and run GUI
    app = CVSSCalculatorGUI()
    app.run()