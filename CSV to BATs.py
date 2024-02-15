import csv
import os

# Function to generate individual BAT scripts
def generate_bat_scripts(csv_file, output_dir):
    with open(csv_file, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        
        # Skip header row
        next(csvreader)
        
        for row in csvreader:
            description = row[0]
            rtsp_url = row[1]
            
            # Create the output directory if it doesn't exist
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Create a BAT script with the description as the filename
            bat_filename = os.path.join(output_dir, f"{description}.bat")
            with open(bat_filename, 'w') as batfile:
                batfile.write(f'"C:\\Program Files\\VideoLAN\\VLC\\vlc.exe" {rtsp_url}\n')

# Replace 'input.csv' with the path to your CSV file
# Replace 'output_directory' with the desired directory path
generate_bat_scripts('C:\\WisDOT\\input.csv', 'C:\\WisDOT\\')
