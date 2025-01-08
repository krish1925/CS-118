# # NOTE: Make sure you have your project files in the ./project directory
# # Will run the autograder and place the results in ./results/results.json

# IMAGE=reliability-is-essential

# run:
# 	docker pull eado0/$(IMAGE)
# 	docker run --rm \
# 		-v ./project:/autograder/submission \
# 		-v ./results:/autograder/results \
# 		eado0/$(IMAGE) \
# 		/autograder/run_autograder && cat results/results.json

# # In case you want to run the autograder manually, use interactive
# interactive:
# 	docker pull eado0/$(IMAGE)
# 	(docker ps | grep $(IMAGE) && \
# 	docker exec -it eado0/$(IMAGE) bash) || \
# 	docker run --rm --name ${IMAGE} -it \
# 		-v ./project:/autograder/submission \
# 		-v ./results:/autograder/results \
# 		eado0/$(IMAGE) bash



# NOTE: Make sure you have your project files in the ./project directory
# Will run the autograder and place the results in ./results/results.json
IMAGE=reliability-is-essential

run:
	docker pull --platform linux/amd64 eado0/$(IMAGE)
	docker run --platform linux/amd64 --rm \
		-v ./project:/autograder/submission \
		-v ./results:/autograder/results \
		eado0/$(IMAGE) \
		/autograder/run_autograder && cat results/results.json

# In case you want to run the autograder manually, use interactive
interactive:
	docker pull --platform linux/amd64 eado0/$(IMAGE)
	# Stop any running container with the same name to avoid conflicts
	(docker stop $(IMAGE) || true) && docker rm $(IMAGE) || true
	docker run --platform linux/amd64 --rm --name $(IMAGE) -it \
		-v ./project:/autograder/submission \
		-v ./results:/autograder/results \
		eado0/$(IMAGE) bash