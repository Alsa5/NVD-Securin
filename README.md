# NVD CVE API

## Overview

This project is a full-stack web application developed to fetch vulnerability data from the National Vulnerability Database (NVD) Common Vulnerabilities and Exposures (CVE) API and store it in a MySQL database. The application provides a user-friendly interface for accessing and managing vulnerability information.

## Features

- **API Integration**: Utilizes the NVD CVE API to fetch the latest vulnerability data.
- **Database Storage**: Stores fetched vulnerability data in a MySQL database for easy retrieval and management.
- **Web Interface**: Provides a web-based interface for users to view, search, and filter vulnerability information.
- **Error Handling**: Implements robust error handling mechanisms to gracefully handle API request failures and database connection issues.
- **Modular Design**: Organizes code into modular components for improved maintainability and extensibility.
- **Optimization**: Optimizes database interactions for improved performance and efficiency.

## Technologies Used

- **Python**: Backend logic and API integration.
- **Flask**: Web framework for building the application.
- **MySQL**: Relational database management system for storing vulnerability data.
- **HTML/CSS**: Frontend presentation and styling.
- **Jinja2**: Template engine for rendering dynamic content in HTML templates.

## Installation

To run the application locally, follow these steps:

1. Clone the repository to your local machine.
2. Install Python and MySQL if not already installed.
3. Install the required Python dependencies using `pip install -r requirements.txt`.
4. Set up a MySQL database and configure the connection details in `config.py`.
5. Run the Flask application using `python app.py`.
6. Access the application in your web browser at `http://localhost:5000`.

## Usage

- Upon launching the application, navigate to the homepage to view the list of vulnerabilities.
- Use the search and filter functionalities to find specific vulnerabilities based on criteria such as CVE ID, severity, etc.
- Click on individual vulnerability entries to view detailed information.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.
