# Render MCP Quick Reference for dory-lat-app

## 🚀 Getting Started

### Set Your Workspace
First, tell Copilot which Render workspace to use:
```
Set my Render workspace to [YOUR_WORKSPACE_NAME]
```

## 📊 Monitoring & Troubleshooting

### Check Deployment Status
```
Show me the status of dory-lat-app
List all my Render services
What's the latest deploy status for dory-lat-app?
```

### View Logs
```
Pull the most recent logs for dory-lat-app
Show me error-level logs from the last hour
Get the startup logs for dory-lat-app
```

### Analyze Metrics
```
What's the CPU usage for dory-lat-app today?
Show me memory usage for my Flask app
What was the busiest traffic day this week?
How many requests did my app handle yesterday?
```

## 🐛 Debugging Specific Issues

### Model Loading Issues
```
Show me logs containing "TensorFlow" or "Keras"
Pull logs with "NLTK" from the last deploy
Find any errors related to model loading
```

### Port Binding Issues
```
Show me logs containing "port" or "bind"
What errors occurred during the last deploy?
Check if the health endpoint is responding
```

### Performance Issues
```
What's the average response time for my service?
Show me the slowest requests from today
Check memory usage during the last hour
```

## 🔧 Service Management

### Deploy History
```
Show me the deploy history for dory-lat-app
What changed in the last deploy?
When was the last successful deploy?
```

### Environment Variables
```
List environment variables for dory-lat-app
Update the PORT variable to 10000
What's the current value of NLTK_DATA?
```

## 💾 Database Operations (if you add one later)

```
Create a new Postgres database called phishing-data with 5GB storage
Query my database for prediction statistics
Show me the most recent 100 predictions
```

## 🎯 App-Specific Prompts

### Check Model Health
```
Verify that all model files are loaded correctly
Check if the /health endpoint is responding
Show me any warnings about NLTK or embeddings
```

### Monitor Predictions
```
How many prediction requests were made today?
Show me any errors in the /predict route
What's the average prediction latency?
```

### Troubleshoot Startup
```
Why didn't my app start on the last deploy?
Show me the build logs from the failed deploy
Check if gunicorn is running properly
```

## 💡 Tips

1. **Be specific**: Instead of "check my app", say "show me error logs for dory-lat-app"
2. **Use time ranges**: "logs from the last hour" or "metrics from yesterday"
3. **Combine actions**: "Pull error logs and check CPU usage for my Flask app"
4. **Ask for analysis**: "Why is my service slow?" or "What caused the last deploy to fail?"

## 🔗 Useful Links

- [Render Dashboard](https://dashboard.render.com)
- [Render MCP Documentation](https://render.com/docs/model-context-protocol)
- [MCP Server GitHub](https://github.com/render-oss/render-mcp-server)

---

**Note**: You can use these prompts directly in GitHub Copilot Chat in VS Code!
