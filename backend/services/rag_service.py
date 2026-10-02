import os
import logging
import chromadb
from config import Config
from services.ollama_service import ollama_service
from services.knowledge_seed import CYBERSECURITY_KNOWLEDGE_SEED

logger = logging.getLogger(__name__)

class RAGService:
    def __init__(self, persist_dir=None):
        self.persist_dir = persist_dir or Config.CHROMA_PERSIST_DIR
        os.makedirs(self.persist_dir, exist_ok=True)
        self.client = chromadb.PersistentClient(path=self.persist_dir)
        self.collection_name = "cybersecurity_knowledge"
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"description": "MITRE ATT&CK, OWASP Top 10, and CVE cybersecurity knowledge"}
        )

    def initialize_and_seed(self, force=False):
        """Seed the collection with cybersecurity knowledge if empty or forced."""
        try:
            current_count = self.collection.count()
            if current_count > 0 and not force:
                logger.info(f"ChromaDB knowledge base already seeded with {current_count} documents.")
                return {"status": "already_seeded", "count": current_count}

            logger.info("Seeding ChromaDB knowledge base with cybersecurity intelligence...")
            if force and current_count > 0:
                self.client.delete_collection(self.collection_name)
                self.collection = self.client.get_or_create_collection(
                    name=self.collection_name,
                    metadata={"description": "MITRE ATT&CK, OWASP Top 10, and CVE cybersecurity knowledge"}
                )

            ids = []
            documents = []
            metadatas = []
            embeddings = []

            for idx, item in enumerate(CYBERSECURITY_KNOWLEDGE_SEED):
                doc_id = f"seed_{item.get('framework', 'GEN').replace(' ', '_').lower()}_{item.get('technique_id', str(idx))}"
                doc_text = (
                    f"[{item['framework']}] {item['technique_id']} - {item['name']}\n"
                    f"Category/Tactic: {item.get('category', 'General')}\n"
                    f"Description: {item['description']}\n"
                    f"Detection & Remediation: {item.get('detection_remediation', '')}"
                )

                # Generate embedding using Ollama nomic-embed-text
                embedding = ollama_service.generate_embedding(doc_text)
                if not embedding or len(embedding) == 0:
                    logger.warning(f"Could not generate embedding for {doc_id}, using fallback zero-vector")
                    embedding = [0.0] * 768

                ids.append(doc_id)
                documents.append(doc_text)
                embeddings.append(embedding)
                metadatas.append({
                    "framework": item["framework"],
                    "technique_id": item["technique_id"],
                    "name": item["name"],
                    "category": item.get("category", "")
                })

            self.collection.add(
                ids=ids,
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas
            )
            logger.info(f"Successfully seeded {len(ids)} cybersecurity knowledge documents into ChromaDB.")
            return {"status": "seeded", "count": len(ids)}
        except Exception as e:
            logger.error(f"Error during RAG initialization/seeding: {e}")
            return {"status": "error", "error": str(e)}

    def search(self, query_text, top_k=5, framework_filter=None):
        """Retrieve relevant cybersecurity knowledge using semantic vector search and exact boosting."""
        try:
            total_items = self.collection.count()
            if total_items == 0:
                self.initialize_and_seed()

            embedding = ollama_service.generate_embedding(query_text)
            if not embedding or len(embedding) == 0:
                logger.warning("Empty embedding generated for query, performing text query fallback")
                # Fallback to pure document query if embedding fails
                query_args = {"query_texts": [query_text], "n_results": min(top_k, max(total_items, 1))}
            else:
                query_args = {"query_embeddings": [embedding], "n_results": min(top_k, max(total_items, 1))}

            if framework_filter:
                query_args["where"] = {"framework": framework_filter}

            results = self.collection.query(**query_args)

            retrieved_docs = []
            if results and results.get("ids") and len(results["ids"]) > 0:
                ids = results["ids"][0]
                docs = results.get("documents", [[]])[0]
                metadatas = results.get("metadatas", [[]])[0]
                distances = results.get("distances", [[]])[0] if "distances" in results else [0.0] * len(ids)

                for doc_id, doc_text, meta, dist in zip(ids, docs, metadatas, distances):
                    # Chroma cosine distance is in range [0, 2], convert to similarity score
                    similarity_score = max(0.0, min(1.0, 1.0 - (dist / 2.0))) if dist is not None else 0.85
                    retrieved_docs.append({
                        "id": doc_id,
                        "content": doc_text,
                        "metadata": meta,
                        "similarity_score": round(similarity_score, 4)
                    })

            # Check for exact technique IDs or CVE mentions in the query and boost them
            upper_query = query_text.upper()
            for seed in CYBERSECURITY_KNOWLEDGE_SEED:
                tid = seed["technique_id"].upper()
                if tid in upper_query:
                    # check if already in retrieved
                    already = any(d["metadata"].get("technique_id") == seed["technique_id"] for d in retrieved_docs)
                    if not already:
                        retrieved_docs.insert(0, {
                            "id": f"boost_{seed['technique_id']}",
                            "content": f"[{seed['framework']}] {seed['technique_id']} - {seed['name']}\nDescription: {seed['description']}\nDetection & Remediation: {seed['detection_remediation']}",
                            "metadata": {
                                "framework": seed["framework"],
                                "technique_id": seed["technique_id"],
                                "name": seed["name"],
                                "category": seed.get("category", "")
                            },
                            "similarity_score": 0.99
                        })

            return retrieved_docs[:top_k]
        except Exception as e:
            logger.error(f"Error during RAG search: {e}")
            return []

    def format_context_for_prompt(self, retrieved_docs):
        """Format retrieved RAG documents into structured context for the LLM prompt."""
        if not retrieved_docs:
            return "No specific MITRE ATT&CK or CVE knowledge matches found in local vector database."

        formatted_chunks = []
        for i, doc in enumerate(retrieved_docs, start=1):
            meta = doc.get("metadata", {})
            header = f"[Source {i}: {meta.get('framework', 'Knowledge Base')} - {meta.get('technique_id', 'N/A')} - {meta.get('name', 'N/A')}]"
            formatted_chunks.append(f"{header}\n{doc.get('content')}")

        return "\n\n".join(formatted_chunks)

    def get_stats(self):
        """Get statistics of current knowledge base collections."""
        try:
            count = self.collection.count()
            frameworks = {"MITRE ATT&CK": 0, "OWASP Top 10": 0, "CVE Knowledge": 0, "Custom": 0}
            
            # Fetch all metadata to summarize counts
            data = self.collection.get(include=["metadatas"])
            for meta in data.get("metadatas", []):
                fw = meta.get("framework", "Custom")
                if fw in frameworks:
                    frameworks[fw] += 1
                else:
                    frameworks["Custom"] += 1

            return {
                "total_documents": count,
                "frameworks": frameworks,
                "vector_backend": "ChromaDB",
                "embedding_model": Config.OLLAMA_EMBED_MODEL
            }
        except Exception as e:
            logger.error(f"Error getting RAG stats: {e}")
            return {"total_documents": 0, "error": str(e)}

    def add_custom_document(self, framework, technique_id, name, category, description, detection_remediation):
        """Add custom intelligence document to ChromaDB."""
        doc_id = f"custom_{framework.replace(' ', '_').lower()}_{technique_id.replace(' ', '_')}"
        doc_text = (
            f"[{framework}] {technique_id} - {name}\n"
            f"Category: {category}\n"
            f"Description: {description}\n"
            f"Detection & Remediation: {detection_remediation}"
        )
        embedding = ollama_service.generate_embedding(doc_text)
        if not embedding:
            embedding = [0.0] * 768

        self.collection.add(
            ids=[doc_id],
            documents=[doc_text],
            embeddings=[embedding],
            metadatas=[{
                "framework": framework,
                "technique_id": technique_id,
                "name": name,
                "category": category
            }]
        )
        return doc_id

rag_service = RAGService()
