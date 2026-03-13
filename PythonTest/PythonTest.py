import os
import requests

getCourseInfo_url = b'https://web.myzhishi.cn/index.php/api/ke/my/my_ke?token=ovhB%253Dud1X23QYmMtXufoKmEyVYz77tEmvtQmGskYUn8pEtf8PlkCRZTiJuugL&dailiid=&appid=dzyk&laiyuan_appid=dzyk&app_type=h5'
getCourseList_url = b'https://web.myzhishi.cn/index.php/api/ke/zhangjie/get_all_zhangjie?w=1&token=pugr%253Dwk2R4zPEuUmUtwT8vEuPswsuuHf-tTYxwkmPtATyu02Qsgv8uU6RsdKL&appid=dzyk&app_type=h5'
getvideoinfo_url  = b'https://web.myzhishi.cn/index.php/api/ke/index/ke_play?token=ovhB%253Dud1X23QYmMtXufoKmEyVYz77tEmvtQmGskYUn8pEtf8PlkCRZTiJuugL&appid=dzyk&app_type=h5'

def download_video(url, path, fileName):

    os.makedirs(path, exist_ok=True)
    print(f"开始下载: {fileName}")
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(path + '/' + fileName + '.mp4', 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024*1024):  # 1MB/块
                if chunk:  # 过滤保持连接的空白块
                    f.write(chunk)
    print(f"下载完成: {fileName}")

def get_video_url(keid, full_path, zsdid):
    print(f"开始获取视频信息: {keid}, {zsdid}")
    response = requests.get(getvideoinfo_url + b"&keid=" + keid + b"&zsdid=" + zsdid)    

    if(response.status_code == 200):
        print("获取课程信息成功")
        video_info = response.json()
        fileName = video_info['data']['ke']['zsd_name']
        urls = video_info['data']['ke']['video_url']['arr']
        download_url = urls[0]["url"]
        for url in urls:
            if(url["title"] == "原画" or url["title"] == "1080p-264" ):
                download_url = url["url"]
                break
        print(f"文件名: {fileName}, url: {download_url}")   # 自动解析JSON

        download_video(download_url, full_path, fileName)

def get_course_list(keid, ke_name):
    print("开始获取课程列表")
    response = requests.get(getCourseList_url + b"&keid=" + keid)
    if(response.status_code == 200):
        print("获取课程列表成功")
        for chapter in response.json()['data']['zhangjie_arr']:
            chapter_name = chapter['zhangjie_name']
            os.makedirs(ke_name + '/' + chapter_name, exist_ok=True)
            print(f"章节名:{chapter_name}")
            for video in chapter['zsd_arr']:
                print(f"视频id:{video['zsdid']},视频名:{video['zsd_name']}")
                get_video_url(keid, ke_name + '/' + chapter_name, video['zsdid'].__str__().encode())
    else:
        print("获取课程列表失败")

def get_course_info():
    print("开始获取课程信息")
    response = requests.get(getCourseInfo_url)
    if(response.status_code == 200):
        print("获取课程信息成功")
        for courseInfo in response.json()['data']:
            course_name = courseInfo['ke_name']
            print(f"课程id:{courseInfo['keid']}, 课程名:{course_name}")
            os.makedirs(course_name, exist_ok=True)
            get_course_list(courseInfo['keid'].__str__().encode(), course_name)
    else:
        print("获取课程信息失败")

get_course_info();
   
