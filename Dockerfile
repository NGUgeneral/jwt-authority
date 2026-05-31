FROM public.ecr.aws/lambda/python:3.11

# Copy requirements first to leverage Docker caching
COPY requirements.txt ${LAMBDA_TASK_ROOT}

# Install dependencies directly into the Lambda task root
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY main.py ${LAMBDA_TASK_ROOT}

# Point Lambda to our Mangum handler inside main.py
CMD [ "main.handler" ]