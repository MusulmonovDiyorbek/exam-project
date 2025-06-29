import { Injectable } from '@nestjs/common';
import { CreateLessonDto } from './dto/create-lesson.dto';
import { UpdateLessonDto } from './dto/update-lesson.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Lesson } from './entities/lesson.entity';
import { Repository } from 'typeorm';
import { ModelService } from 'src/model/model.service';

@Injectable()
export class LessonsService {
  constructor(
    @InjectRepository(Lesson)
    private readonly lessonRepo: Repository<Lesson>,
    private modelService: ModelService
  ) { }

  async create(dto: CreateLessonDto) {
    const model1 = await this.modelService.findOne(dto.modelId);
    if (!model1) throw new Error('Model not found');
    const lesson = this.lessonRepo.create({ ...dto, model: model1 });

    return this.lessonRepo.save(lesson);
  }

  async findAll() {
    return this.lessonRepo.find({ relations: ['model'] });
  }

  async findByModelId(modelId: number) {
    return this.lessonRepo.find({ where: { model: { id: modelId } }, relations: ['model'] });
  }

  async findOne(id: number) {
    const lesson = await this.lessonRepo.findOne({
      where: { id },
      relations: ['model'],
    });
    if (!lesson) {
      throw new Error('Bunday dars mavjud emas');
    }
    return lesson;
  }

  async update(id:number,dto:UpdateLessonDto){
    const lesson = await this.lessonRepo.findOneBy({id});
    if(!lesson){
      throw new Error('Bunday dars mavjud emas');
    }
    console.log(dto);
    
    Object.assign(lesson,dto);
    return this.lessonRepo.save(lesson);
  }

  async remove(id:number){
    const lesson = await this.lessonRepo.findBy({id});
    if(!lesson){
      throw new Error('Bunday dars mavjud emas');
    }
    return this.lessonRepo.remove(lesson);
  }
}