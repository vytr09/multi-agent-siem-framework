"""
LLM-as-Judge Evaluator
Uses Gemini API to evaluate agent outputs with structured prompts
"""

import asyncio
import json
import os
from typing import Dict, Any, List, Optional
from google import genai
from google.genai import types


class LLMJudge:
    """
    LLM-as-Judge evaluator using Gemini API.
    
    Provides structured evaluation of agent outputs with scoring
    and detailed explanations.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Get API key
        self.api_key = config.get("api_key") or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API key required for LLM Judge")
        
        # Model configuration
        self.model_name = config.get("model", "gemini-2.0-flash-lite")
        self.temperature = config.get("temperature", 0.3)
        self.max_tokens = config.get("max_tokens", 2000)
        
        # Initialize client
        self.client = genai.Client(api_key=self.api_key)
        
        # Judge configuration
        self.judge_persona = config.get(
            "persona", 
            "expert cybersecurity researcher and red team operator"
        )
        
        self.enable_detailed_feedback = config.get("detailed_feedback", True)
        self.enable_confidence_scores = config.get("confidence_scores", True)
    
    def _get_generation_config(self) -> types.GenerateContentConfig:
        """Create generation configuration"""
        return types.GenerateContentConfig(
            temperature=self.temperature,
            max_output_tokens=self.max_tokens,
            top_p=0.95,
            top_k=40,
            safety_settings=[
                types.SafetySetting(
                    category='HARM_CATEGORY_HARASSMENT',
                    threshold='BLOCK_NONE'
                ),
                types.SafetySetting(
                    category='HARM_CATEGORY_HATE_SPEECH',
                    threshold='BLOCK_NONE'
                ),
                types.SafetySetting(
                    category='HARM_CATEGORY_SEXUALLY_EXPLICIT',
                    threshold='BLOCK_NONE'
                ),
                types.SafetySetting(
                    category='HARM_CATEGORY_DANGEROUS_CONTENT',
                    threshold='BLOCK_NONE'
                ),
            ]
        )
    
    async def evaluate(
        self,
        item: Dict[str, Any],
        criteria: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate an item against multiple criteria.
        
        Args:
            item: Item to evaluate
            criteria: List of evaluation criteria with descriptions
            context: Optional additional context
            
        Returns:
            Evaluation results with scores and explanations
        """
        prompt = self._build_evaluation_prompt(item, criteria, context)
        
        try:
            response = await self._generate(prompt)
            result = self._parse_evaluation_response(response)
            return result
            
        except Exception as e:
            print(f"[LLM Judge] Evaluation error: {e}")
            return self._get_fallback_result(criteria)
    
    def _build_evaluation_prompt(
        self,
        item: Dict[str, Any],
        criteria: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build structured evaluation prompt"""
        
        prompt_parts = [
            f"You are an {self.judge_persona} evaluating cybersecurity artifacts.",
            "",
            "=== YOUR TASK ===",
            "Evaluate the following item against each criterion and provide:",
            "1. A score (0-10 scale)",
            "2. A detailed explanation of your assessment",
            "3. Specific strengths and weaknesses",
            "4. Your confidence in the evaluation (0-1 scale)",
            "",
            "=== ITEM TO EVALUATE ===",
            json.dumps(item, indent=2),
            ""
        ]
        
        # Add context if provided
        if context:
            prompt_parts.extend([
                "=== ADDITIONAL CONTEXT ===",
                json.dumps(context, indent=2),
                ""
            ])
        
        # Add evaluation criteria
        prompt_parts.extend([
            "=== EVALUATION CRITERIA ===",
            ""
        ])
        
        for i, criterion in enumerate(criteria, 1):
            prompt_parts.extend([
                f"**Criterion {i}: {criterion['name']}**",
                f"Description: {criterion['description']}",
                f"Weight: {criterion.get('weight', 1.0)}",
                ""
            ])
        
        # Add output format
        prompt_parts.extend([
            "=== OUTPUT FORMAT ===",
            "Respond with ONLY valid JSON in this exact format:",
            "{",
            '  "evaluations": [',
            "    {",
            '      "criterion": "criterion name",',
            '      "score": 0-10,',
            '      "explanation": "detailed reasoning",',
            '      "strengths": ["strength 1", "strength 2"],',
            '      "weaknesses": ["weakness 1", "weakness 2"],',
            '      "confidence": 0.0-1.0',
            "    }",
            "  ],",
            '  "overall_assessment": "summary of overall quality",',
            '  "recommendations": ["recommendation 1", "recommendation 2"]',
            "}",
            "",
            "Begin evaluation:"
        ])
        
        return "\n".join(prompt_parts)
    
    async def _generate(self, prompt: str) -> str:
        """Generate response from Gemini"""
        
        def _generate_sync():
            config = self._get_generation_config()
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config
            )
            
            # Extract text
            if hasattr(response, 'text') and response.text:
                return response.text
            
            if hasattr(response, "candidates") and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'content'):
                    content = candidate.content
                    if hasattr(content, "parts") and content.parts:
                        texts = []
                        for part in content.parts:
                            if hasattr(part, "text") and part.text:
                                texts.append(part.text)
                        if texts:
                            return ''.join(texts)
            
            return ""
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _generate_sync)
    
    def _parse_evaluation_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM evaluation response"""
        
        # Clean response
        response = response.strip()
        
        # Remove markdown code blocks
        if response.startswith("```"):
            lines = response.split("\n")
            response = "\n".join(lines[1:-1])
            if response.startswith("json"):
                response = "\n".join(response.split("\n")[1:])
        
        try:
            return json.loads(response)
        except json.JSONDecodeError as e:
            print(f"[LLM Judge] Failed to parse response: {e}")
            return {
                "evaluations": [],
                "overall_assessment": "Failed to parse LLM response",
                "recommendations": []
            }
    
    def _get_fallback_result(self, criteria: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get fallback result when LLM fails"""
        return {
            "evaluations": [
                {
                    "criterion": c["name"],
                    "score": 5.0,
                    "explanation": "Evaluation failed - using default score",
                    "strengths": [],
                    "weaknesses": ["Evaluation error"],
                    "confidence": 0.0
                }
                for c in criteria
            ],
            "overall_assessment": "Evaluation failed - fallback result",
            "recommendations": ["Re-run evaluation"]
        }
    
    async def compare(
        self,
        item_a: Dict[str, Any],
        item_b: Dict[str, Any],
        criteria: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Compare two items against a criterion.
        
        Args:
            item_a: First item
            item_b: Second item
            criteria: Comparison criteria
            context: Optional context
            
        Returns:
            Comparison result with preference and reasoning
        """
        prompt = self._build_comparison_prompt(item_a, item_b, criteria, context)
        
        try:
            response = await self._generate(prompt)
            result = self._parse_comparison_response(response)
            return result
            
        except Exception as e:
            print(f"[LLM Judge] Comparison error: {e}")
            return {
                "preference": "neutral",
                "reasoning": f"Comparison failed: {e}",
                "confidence": 0.0
            }
    
    def _build_comparison_prompt(
        self,
        item_a: Dict[str, Any],
        item_b: Dict[str, Any],
        criteria: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build comparison prompt"""
        
        prompt_parts = [
            f"You are an {self.judge_persona} comparing two cybersecurity artifacts.",
            "",
            "=== COMPARISON TASK ===",
            f"Compare Item A and Item B based on: {criteria}",
            "",
            "Provide:",
            "1. Which item is better (A, B, or neutral)",
            "2. Detailed reasoning for your choice",
            "3. Confidence in your assessment (0-1)",
            "",
            "=== ITEM A ===",
            json.dumps(item_a, indent=2),
            "",
            "=== ITEM B ===",
            json.dumps(item_b, indent=2),
            ""
        ]
        
        if context:
            prompt_parts.extend([
                "=== CONTEXT ===",
                json.dumps(context, indent=2),
                ""
            ])
        
        prompt_parts.extend([
            "=== OUTPUT FORMAT ===",
            "Respond with ONLY valid JSON:",
            "{",
            '  "preference": "A" | "B" | "neutral",',
            '  "reasoning": "detailed explanation",',
            '  "confidence": 0.0-1.0,',
            '  "item_a_strengths": ["strength 1", "strength 2"],',
            '  "item_b_strengths": ["strength 1", "strength 2"]',
            "}",
            "",
            "Begin comparison:"
        ])
        
        return "\n".join(prompt_parts)
    
    def _parse_comparison_response(self, response: str) -> Dict[str, Any]:
        """Parse comparison response"""
        
        response = response.strip()
        
        if response.startswith("```"):
            lines = response.split("\n")
            response = "\n".join(lines[1:-1])
            if response.startswith("json"):
                response = "\n".join(response.split("\n")[1:])
        
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {
                "preference": "neutral",
                "reasoning": "Failed to parse response",
                "confidence": 0.0,
                "item_a_strengths": [],
                "item_b_strengths": []
            }