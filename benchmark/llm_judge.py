"""
LLM-as-Judge Evaluator
Uses Gemini API to evaluate agent outputs with structured prompts
FIXED: Batch evaluation to avoid JSON truncation
"""
from dotenv import load_dotenv
load_dotenv()

import asyncio
import json
import os
import re
from typing import Dict, Any, List, Optional
try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    # Mock types for environments without the SDK
    class MockTypes:
        GenerateContentConfig = Any
        SafetySetting = Any
    types = MockTypes()


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
        self.max_tokens = config.get("max_tokens", 4000)  # Increased default
        
        # Initialize client
        self.client = genai.Client(api_key=self.api_key)
        
        # Judge configuration
        self.judge_persona = config.get(
            "persona", 
            "expert cybersecurity researcher and red team operator"
        )
        
        self.enable_detailed_feedback = config.get("detailed_feedback", True)
        self.enable_confidence_scores = config.get("confidence_scores", True)
    
    async def test_connection(self) -> bool:
        """Test LLM connection with a simple query"""
        try:
            print("[LLM Judge] Testing connection to Gemini API...")
            test_prompt = "Respond with only the JSON: {\"status\": \"ok\", \"message\": \"connection successful\"}"
            response = await self._generate(test_prompt, max_retries=2)
            
            if response and len(response.strip()) > 0:
                print("[LLM Judge] Connection successful")
                return True
            else:
                print("[LLM Judge] Empty response from API")
                return False
                
        except Exception as e:
            print(f"[LLM Judge] Connection failed: {e}")
            return False
    
    def _get_generation_config(self) -> types.GenerateContentConfig:
        """Create generation configuration without safety_settings"""
        return types.GenerateContentConfig(
            temperature=self.temperature,
            max_output_tokens=self.max_tokens,
            top_p=0.95,
            top_k=40
        )
    
    def _get_safety_settings(self) -> List[types.SafetySetting]:
        """Create safety settings separately"""
        return [
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
    
    async def evaluate(
        self,
        item: Dict[str, Any],
        criteria: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
        batch_size: int = 4
    ) -> Dict[str, Any]:
        """
        Evaluate an item against multiple criteria with automatic batching.
        
        Args:
            item: Item to evaluate
            criteria: List of evaluation criteria with descriptions
            context: Optional additional context
            batch_size: Number of criteria to evaluate per API call (default: 4)
            
        Returns:
            Evaluation results with scores and explanations
        """
        
        # If criteria count <= batch_size, evaluate all at once
        if len(criteria) <= batch_size:
            return await self._evaluate_batch(item, criteria, context)
        
        # Otherwise, split into batches
        print(f"[LLM Judge] Splitting {len(criteria)} criteria into batches of {batch_size}")
        
        all_evaluations = []
        total_batches = (len(criteria) + batch_size - 1) // batch_size
        
        for i in range(0, len(criteria), batch_size):
            batch = criteria[i:i+batch_size]
            batch_num = i // batch_size + 1
            
            print(f"[LLM Judge] Evaluating batch {batch_num}/{total_batches} ({len(batch)} criteria)...")
            
            try:
                result = await self._evaluate_batch(item, batch, context)
                batch_evals = result.get("evaluations", [])
                all_evaluations.extend(batch_evals)
                
                # Small delay between batches to avoid rate limiting
                if i + batch_size < len(criteria):
                    await asyncio.sleep(0.5)
                    
            except Exception as e:
                print(f"[LLM Judge] Batch {batch_num} failed: {e}")
                # Add fallback scores for this batch
                all_evaluations.extend([
                    {
                        "criterion": c["name"],
                        "score": 5.0,
                        "explanation": f"Evaluation failed for this criterion",
                        "strengths": [],
                        "weaknesses": [],
                        "confidence": 0.0
                    }
                    for c in batch
                ])
        
        # Combine results
        return {
            "evaluations": all_evaluations,
            "overall_assessment": f"Evaluated {len(all_evaluations)} criteria across {total_batches} batches",
            "recommendations": []
        }
    
    async def _evaluate_batch(
        self,
        item: Dict[str, Any],
        criteria: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Evaluate a single batch of criteria"""
        
        prompt = self._build_evaluation_prompt(item, criteria, context)
        
        try:
            response = await self._generate(prompt)
            result = self._parse_evaluation_response(response)
            
            # Validate result structure
            if not result.get("evaluations"):
                print(f"[LLM Judge] Warning: No evaluations in result")
                return self._get_fallback_result(criteria)
            
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
            "3. Specific strengths and weaknesses (2-3 each, keep concise)",
            "4. Your confidence in the evaluation (0-1 scale)",
            "",
            "=== ITEM TO EVALUATE ===",
            json.dumps(item, indent=2)[:2000],  # Truncate if too long
            ""
        ]
        
        # Add context if provided
        if context:
            prompt_parts.extend([
                "=== ADDITIONAL CONTEXT ===",
                json.dumps(context, indent=2)[:1000],
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
                f"Description: {criterion['description'][:500]}",  # Truncate long descriptions
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
            '      "explanation": "detailed reasoning (2-3 sentences)",',
            '      "strengths": ["strength 1", "strength 2"],',
            '      "weaknesses": ["weakness 1", "weakness 2"],',
            '      "confidence": 0.0-1.0',
            "    }",
            "  ],",
            '  "overall_assessment": "brief summary",',
            '  "recommendations": ["rec 1", "rec 2"]',
            "}",
            "",
            "IMPORTANT: Keep explanations concise. Respond with complete, valid JSON only.",
            "",
            "Begin evaluation:"
        ])
        
        return "\n".join(prompt_parts)
    
    async def _generate(self, prompt: str, max_retries: int = 3) -> str:
        """Generate response from Gemini with retry logic"""
        
        def _generate_sync():
            config = self._get_generation_config()
            
            # Try to pass safety_settings in generate_content call
            try:
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=config,
                    safety_settings=self._get_safety_settings()
                )
            except TypeError:
                # If safety_settings not supported in generate_content, try without it
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
            
            # Check for blocked content or errors
            if hasattr(response, "candidates") and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'finish_reason'):
                    finish_reason = str(candidate.finish_reason)
                    if 'SAFETY' in finish_reason or 'BLOCKED' in finish_reason:
                        raise ValueError(f"Content blocked by safety filters: {finish_reason}")
            
            return ""
        
        # Retry logic
        last_error = None
        for attempt in range(max_retries):
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, _generate_sync)
                
                if result and len(result.strip()) > 0:
                    return result
                else:
                    last_error = ValueError("Empty response from LLM")
                    if attempt < max_retries - 1:
                        print(f"[LLM Judge] Empty response, retrying ({attempt + 1}/{max_retries})...")
                        await asyncio.sleep(1)
                    
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    print(f"[LLM Judge] Error: {e}, retrying ({attempt + 1}/{max_retries})...")
                    await asyncio.sleep(2)
                else:
                    print(f"[LLM Judge] All retries failed: {e}")
        
        # If all retries failed, raise the last error
        if last_error:
            raise last_error
        else:
            raise ValueError("Failed to generate response after all retries")
    
    def _parse_evaluation_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM evaluation response with robust error handling"""
        
        # Clean response
        response = response.strip()
        
        if not response:
            print(f"[LLM Judge] Empty response received")
            return {
                "evaluations": [],
                "overall_assessment": "Empty response from LLM",
                "recommendations": []
            }
        
        # Remove markdown code blocks
        if response.startswith("```"):
            lines = response.split("\n")
            if len(lines) > 2:
                response = "\n".join(lines[1:-1])
                if response.startswith("json"):
                    response = "\n".join(response.split("\n")[1:])
        
        # Try to fix common JSON issues
        response = self._fix_json_issues(response)
        
        # Try to find and parse JSON
        try:
            # First try direct parsing
            return json.loads(response)
        except json.JSONDecodeError as e:
            print(f"[LLM Judge] JSON parse error: {e}")
            
            # Try to extract and fix JSON
            json_text = self._extract_json(response)
            if json_text:
                try:
                    return json.loads(json_text)
                except json.JSONDecodeError:
                    print(f"[LLM Judge] Failed to parse extracted JSON")
            
            # Last resort: try to salvage partial evaluations
            salvaged = self._salvage_partial_json(response)
            if salvaged and salvaged.get("evaluations"):
                print(f"[LLM Judge] Salvaged {len(salvaged['evaluations'])} partial evaluations")
                return salvaged
            
            print(f"[LLM Judge] Response preview: {response[:500]}")
            return {
                "evaluations": [],
                "overall_assessment": "Failed to parse LLM response",
                "recommendations": []
            }
    
    def _fix_json_issues(self, text: str) -> str:
        """Fix common JSON formatting issues"""
        # Remove trailing commas before closing brackets
        text = re.sub(r',(\s*[}\]])', r'\1', text)
        return text
    
    def _extract_json(self, text: str) -> Optional[str]:
        """Extract JSON object from text"""
        # Find outermost JSON object
        brace_count = 0
        start_idx = -1
        
        for i, char in enumerate(text):
            if char == '{':
                if brace_count == 0:
                    start_idx = i
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0 and start_idx >= 0:
                    return text[start_idx:i+1]
        
        return None
    
    def _salvage_partial_json(self, text: str) -> Dict[str, Any]:
        """Try to salvage partial evaluations from incomplete JSON"""
        evaluations = []
        
        # Look for evaluation objects
        pattern = r'\{\s*"criterion":\s*"([^"]+)"[^}]*"score":\s*(\d+\.?\d*)[^}]*"explanation":\s*"([^"]*)"'
        matches = re.finditer(pattern, text, re.DOTALL)
        
        for match in matches:
            criterion, score, explanation = match.groups()
            try:
                evaluations.append({
                    "criterion": criterion,
                    "score": float(score),
                    "explanation": explanation[:500],  # Truncate long explanations
                    "strengths": [],
                    "weaknesses": [],
                    "confidence": 0.7  # Lower confidence for partial data
                })
            except (ValueError, TypeError):
                continue
        
        if evaluations:
            return {
                "evaluations": evaluations,
                "overall_assessment": "Partial evaluation recovered from incomplete response",
                "recommendations": ["Re-run for complete evaluation"]
            }
        
        return {
            "evaluations": [],
            "overall_assessment": "Failed to parse response",
            "recommendations": []
        }
    
    def _get_fallback_result(self, criteria: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get fallback result when LLM fails - with better default scores"""
        return {
            "evaluations": [
                {
                    "criterion": c["name"],
                    "score": 5.0,  # Neutral score
                    "explanation": f"LLM evaluation unavailable - using neutral score for {c['name']}",
                    "strengths": ["Unable to evaluate - LLM error"],
                    "weaknesses": ["Evaluation not performed due to technical error"],
                    "confidence": 0.0
                }
                for c in criteria
            ],
            "overall_assessment": "Evaluation failed - LLM unavailable. Scores defaulted to neutral (5.0/10). Manual review recommended.",
            "recommendations": [
                "Re-run evaluation with working LLM connection",
                "Check API key and network connectivity",
                "Review Gemini API quotas and rate limits"
            ]
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