"""
LLM-as-Judge Evaluator
Uses Core Framework's LLMProviderManager for evaluation
Refactored to remove direct google.genai dependency
"""
from dotenv import load_dotenv
load_dotenv()

import asyncio
import json
import re
from typing import Dict, Any, List, Optional
from langchain_core.messages import HumanMessage
from core.langchain_integration import get_llm_manager

class LLMJudge:
    """
    LLM-as-Judge evaluator using Framework's LLM Integration.
    
    Provides structured evaluation of agent outputs with scoring
    and detailed explanations.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Initialize LLM Manager
        self.llm_manager = get_llm_manager()
        
        # Model configuration
        self.model_name = config.get("model", "default") # Will use provider manager's default
        self.temperature = config.get("temperature", 0.3)
        self.max_tokens = config.get("max_tokens", 4000)
        
        # Judge configuration
        self.judge_persona = config.get(
            "persona", 
            "expert cybersecurity researcher and red team operator"
        )
        
        self.enable_detailed_feedback = config.get("detailed_feedback", True)
        self.enable_confidence_scores = config.get("confidence_scores", True)

    async def _get_llm(self):
        """Get configured LLM from manager"""
        # Try to get specific model if configured, else default
        # Note: LLMProviderManager logic handles fallback
        return self.llm_manager.get_chat_model(
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )
    
    async def test_connection(self) -> bool:
        """Test LLM connection with a simple query"""
        try:
            # print("[LLM Judge] Testing connection to LLM Provider...")
            llm = await self._get_llm()
            test_prompt = "Respond with only the JSON: {\"status\": \"ok\", \"message\": \"connection successful\"}"
            response = await llm.ainvoke([HumanMessage(content=test_prompt)])
            
            if response and response.content:
                # print(f"[LLM Judge] Connection successful (Provider: {type(llm).__name__})")
                return True
            else:
                # print("[LLM Judge] Empty response from API")
                return False
                
        except Exception as e:
            # print(f"[LLM Judge] Connection failed: {e}")
            return False
    
    async def evaluate(
        self,
        item: Dict[str, Any],
        criteria: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
        batch_size: int = 4
    ) -> Dict[str, Any]:
        """
        Evaluate an item against multiple criteria with automatic batching.
        """
        
        # If criteria count <= batch_size, evaluate all at once
        if len(criteria) <= batch_size:
            return await self._evaluate_batch(item, criteria, context)
        
        # Otherwise, split into batches
        # print(f"[LLM Judge] Splitting {len(criteria)} criteria into batches of {batch_size}")
        
        all_evaluations = []
        total_batches = (len(criteria) + batch_size - 1) // batch_size
        
        for i in range(0, len(criteria), batch_size):
            batch = criteria[i:i+batch_size]
            batch_num = i // batch_size + 1
            
            # print(f"[LLM Judge] Evaluating batch {batch_num}/{total_batches} ({len(batch)} criteria)...")
            
            try:
                result = await self._evaluate_batch(item, batch, context)
                batch_evals = result.get("evaluations", [])
                all_evaluations.extend(batch_evals)
                
                # Delay between batches to avoid rate limiting
                if i + batch_size < len(criteria):
                    # print(f"[LLM Judge] Sleeping 10s between batches...")
                    await asyncio.sleep(10)
                    
            except Exception as e:
                print(f"[LLM Judge] Batch {batch_num} failed: {e}")
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
        
        if context:
            prompt_parts.extend([
                "=== ADDITIONAL CONTEXT ===",
                json.dumps(context, indent=2)[:1000],
                ""
            ])
        
        prompt_parts.extend([
            "=== EVALUATION CRITERIA ===",
            ""
        ])
        
        for i, criterion in enumerate(criteria, 1):
            prompt_parts.extend([
                f"**Criterion {i}: {criterion['name']}**",
                f"Description: {criterion['description'][:500]}",
                f"Weight: {criterion.get('weight', 1.0)}",
                ""
            ])
        
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
    
    async def _generate(self, prompt: str, max_retries: int = 5) -> str:
        """Generate response using Framework LLM with retry logic"""
        
        # Initial get
        llm = await self._get_llm()
        
        last_error = None
        for attempt in range(max_retries):
            try:
                # Use ainvoke for async execution
                response = await llm.ainvoke([HumanMessage(content=prompt)])
                content = response.content
                
                if content and len(content.strip()) > 0:
                    return content
                else:
                    last_error = ValueError("Empty response from LLM")
                    if attempt < max_retries - 1:
                        print(f"[LLM Judge] Empty response, retrying ({attempt + 1}/{max_retries})...")
                        await asyncio.sleep(1)
                    
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    print(f"[LLM Judge] Error: {repr(e)}")
                    
                    # Backoff strategy with Rotation
                    # Check for various forms of rate limit errors
                    error_str = str(e).lower()
                    error_repr = repr(e).lower()
                    
                    if ("429" in error_str or 
                        "too many requests" in error_str or 
                        "ratelimit" in error_repr or 
                        "quota" in error_str):
                        
                        print(f"[LLM Judge] Hit Rate Limit (429/Quota). Initiating Provider Rotation...")
                        
                        # Force provider rotation
                        if hasattr(self.llm_manager, 'rotate_provider'):
                            self.llm_manager.rotate_provider()
                            # CRITICAL: Invalidate local cache and re-fetch LLM
                            self.llm = None
                            llm = await self._get_llm()
                            print(f"[LLM Judge] Rotated to new provider: {type(llm).__name__}")
                        
                        # Small delay to let rotation settle (2s)
                        await asyncio.sleep(2)
                    else:
                        # Exponential backoff for other errors: 2, 4, 8...
                        sleep_time = 2 ** (attempt + 1)
                        print(f"[LLM Judge] Retrying in {sleep_time}s...")
                        await asyncio.sleep(sleep_time)
                else:
                    print(f"[LLM Judge] All retries failed: {e}")
        
        if last_error:
            raise last_error
        else:
            raise ValueError("Failed to generate response after all retries")
    
    def _parse_evaluation_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM evaluation response with robust error handling"""
        response = response.strip()
        
        if not response:
            return self._get_empty_response()
        
        if response.startswith("```"):
            lines = response.split("\n")
            if len(lines) > 2:
                response = "\n".join(lines[1:-1])
                if response.startswith("json"):
                    response = "\n".join(response.split("\n")[1:])
        
        response = self._fix_json_issues(response)
        
        try:
            return json.loads(response)
        except json.JSONDecodeError as e:
            print(f"[LLM Judge] JSON parse error: {e}")
            
            json_text = self._extract_json(response)
            if json_text:
                try:
                    return json.loads(json_text)
                except json.JSONDecodeError:
                    pass
            
            salvaged = self._salvage_partial_json(response)
            if salvaged and salvaged.get("evaluations"):
                return salvaged
            
            return self._get_empty_response("Failed to parse LLM response")
            
    def _get_empty_response(self, msg="Empty response") -> Dict[str, Any]:
        return {
            "evaluations": [],
            "overall_assessment": msg,
            "recommendations": []
        }

    def _fix_json_issues(self, text: str) -> str:
        text = re.sub(r',(\s*[}\]])', r'\1', text)
        return text
    
    def _extract_json(self, text: str) -> Optional[str]:
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
        evaluations = []
        pattern = r'\{\s*"criterion":\s*"([^"]+)"[^}]*"score":\s*(\d+\.?\d*)[^}]*"explanation":\s*"([^"]*)"'
        matches = re.finditer(pattern, text, re.DOTALL)
        
        for match in matches:
            criterion, score, explanation = match.groups()
            try:
                evaluations.append({
                    "criterion": criterion,
                    "score": float(score),
                    "explanation": explanation[:500],
                    "strengths": [],
                    "weaknesses": [],
                    "confidence": 0.5
                })
            except (ValueError, TypeError):
                continue
        
        if evaluations:
            return {
                "evaluations": evaluations,
                "overall_assessment": "Partial evaluation recovered",
                "recommendations": []
            }
        return {}
    
    def _get_fallback_result(self, criteria: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "evaluations": [
                {
                    "criterion": c["name"],
                    "score": 5.0,
                    "explanation": f"LLM evaluation unavailable - using neutral score",
                    "strengths": [],
                    "weaknesses": [],
                    "confidence": 0.0
                }
                for c in criteria
            ],
            "overall_assessment": "Evaluation failed - LLM unavailable.",
            "recommendations": []
        }

    async def compare(
        self,
        item_a: Dict[str, Any],
        item_b: Dict[str, Any],
        criteria: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Compare two items"""
        prompt = self._build_comparison_prompt(item_a, item_b, criteria, context)
        try:
            response = await self._generate(prompt)
            return self._parse_comparison_response(response)
        except Exception as e:
            print(f"[LLM Judge] Comparison error: {e}")
            return {"preference": "neutral", "reasoning": str(e), "confidence": 0.0}

    def _build_comparison_prompt(self, item_a, item_b, criteria, context) -> str:
        prompt_parts = [
            f"You are an {self.judge_persona} comparing two cybersecurity artifacts.",
            "",
            "=== COMPARISON TASK ===",
            f"Compare Item A and Item B based on: {criteria}",
            "",
            "=== ITEM A ===",
            json.dumps(item_a, indent=2),
            "",
            "=== ITEM B ===",
            json.dumps(item_b, indent=2),
            ""
        ]
        if context:
            prompt_parts += ["=== CONTEXT ===", json.dumps(context, indent=2), ""]
            
        prompt_parts += [
            "=== OUTPUT FORMAT ===",
            "Respond with ONLY valid JSON: { \"preference\": \"A\" | \"B\" | \"neutral\", \"reasoning\": \"...\", \"confidence\": 0.9 }"
        ]
        return "\n".join(prompt_parts)

    def _parse_comparison_response(self, response: str) -> Dict[str, Any]:
        response = response.strip()
        if response.startswith("```"):
             lines = response.split("\n")
             if len(lines) > 2:
                response = "\n".join(lines[1:-1])
                if response.startswith("json"):
                    response = "\n".join(response.split("\n")[1:])
        try:
            return json.loads(response)
        except:
             return {"preference": "neutral", "reasoning": "Failed to parse", "confidence": 0.0}