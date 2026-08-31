const { GoogleGenAI } = require('@google/genai');

class AIService {
  constructor() {
    const apiKey = process.env.GEMINI_API_KEY || process.env.AI_API_KEY;
    this.client = apiKey ? new GoogleGenAI({ apiKey }) : null;
    this.model = process.env.AI_MODEL || 'gemini-2.5-flash';
  }

  async chat(prompt) {
    if (!this.client) {
      throw Object.assign(new Error('AI provider is not configured'), { statusCode: 503 });
    }

    const response = await this.client.models.generateContent({
      model: this.model,
      contents: prompt,
    });

    return response.text || response.output_text || 'AI response unavailable';
  }
}

module.exports = { AIService };
